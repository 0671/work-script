import logging
import json
import yaml
import requests
import urllib3
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.DEBUG)

with open('env.yml', 'r', encoding='utf-8')as f:
    envdata = yaml.load(f, Loader=yaml.FullLoader)

CT_HOST = envdata['CT_HOST'] # 长亭waf地址
CT_API_TOKEN = envdata['CT_API_TOKEN']  # 长亭waf token
HEADERS = {"API-TOKEN": CT_API_TOKEN, "content-type":"application/json;charset=UTF-8"}

cert_list = requests.get(
    CT_HOST + "/api/CertAPI?count=1000&offset=0", 
    headers=HEADERS, 
    verify=False).json()['data']['items']

SLACK_BOT_TOKEN=envdata['SLACK_BOT_TOKEN']
SLACK_APP_TOKEN=envdata['SLACK_APP_TOKEN']

MANAGER_ID = envdata['MANAGER_ID']
app = App(token=SLACK_BOT_TOKEN)

@app.command("/ct-hello")
def hello_command(ack, body):
    user_id = body["user_id"]
    ack(f"Hi <@{user_id}>!")

@app.event("app_mention")
def event_test(event, say):
    say(f"Hi there, <@{event['user']}>!")

def ack_cmd(ack):
    ack()
    
def open_modal(body, client):
    manager_id = MANAGER_ID
    logging.error(json.dumps(body))
    # user_id = body['user']['id']
    channel_id = body['channel_id']
    user_id = body['user_id']
    if user_id !=MANAGER_ID:
        client.views_open(
            trigger_id=body["trigger_id"],
            view = {
                "type": "modal",
                "title": {
                    "type": "plain_text",
                    "text": "无权使用",
                },
                "close": {
                    "type": "plain_text",
                    "text": "Cancel",
                },
                "blocks": [],
            }
        )
    else:
        client.views_open(
            trigger_id=body["trigger_id"],
            view={
                "type": "modal",
                "callback_id": "ct-domain-new-submission",
                "submit": {
                    "type": "plain_text",
                    "text": "提交",
                },
                "close": {
                    "type": "plain_text",
                    "text": "取消",
                },
                "title": {
                    "type": "plain_text",
                    "text": "新建CT防护域名",
                },
                'private_metadata':channel_id,
                "blocks": [
                    {
                        "type": "input",
                        "block_id": "q1",
                        "label": {
                            "type": "plain_text",
                            "text": "域名",
                        },
                        "element": {
                            "action_id": "domain",
                            "type": "plain_text_input",
                        },
                    },
                    {
                        "type": "input",
                        "block_id": "q2",
                        "label": {
                            "type": "plain_text",
                            "text": "后端地址",
                        },
                        "element": {
                            "action_id": "backend-server",
                            "type": "plain_text_input",
                        },
                    },
                    {
                        "type": "input",
                        "block_id": "q3",
                        "label": {
                            "type": "plain_text",
                            "text": "证书",
                        },
                        "element": {
                            "type": "external_select",
                            "action_id": "cert",
                            "min_query_length": 0,
                            "placeholder": {
                                "type": "plain_text",
                                "text": "选择域名适用的证书",
                            },
                        },
                    },
                    {
                        "type": "input",
                        "block_id": "q4",
                        "label": {
                            "type": "plain_text",
                            "text": "备注",
                        },
                        "element": {
                            "action_id": "remark",
                            "type": "plain_text_input",
                        },
                    },
                ],
            },
        )


app.command("/ct-domain-new")(
    ack=ack_cmd,
    lazy=[open_modal],
)

all_options = [
    {
        "text": {"type": "plain_text", "text": c['name']},
        "value": str(c['id'])
    } for c in cert_list
]


@app.options("cert")
def external_data_source_handler(ack, body):
    keyword = body.get("value")
    if keyword is not None and len(keyword) > 0:
        options = [o for o in all_options if keyword in o["text"]["text"]]
        ack(options=options)
    else:
        ack(options=all_options)


@app.view("ct-domain-new-submission")
def submission(ack, body, say):
    print(json.dumps(body))

    domain = body['view']['state']['values']['q1']['domain']['value']
    backend = body['view']['state']['values']['q2']['backend-server']['value']
    cert_id = int(body['view']['state']['values']['q3']['cert']['selected_option']['value'])
    remark = body['view']['state']['values']['q4']['remark']['value']
    channel_id = body['view']['private_metadata']
    
    config={}
    config['config_name'] = domain.strip()
    config['server_names'] =[i.strip() for i in domain.split(',')]
    config['backend_config_host'] = backend.strip()
    config['remark'] = remark.strip()
    config['is_enabled'] = True
    config['ssl_cert'] = cert_id

    show_text = f'[*] 新配置 {config["server_names"]}-->{config["backend_config_host"]}, 名字:{config["config_name"]}, 证书id:{config["ssl_cert"]}, 注释:{config["remark"]}, 启用:{config["is_enabled"]}'

    logging.debug(show_text )

    domain_profile={}
    with open('domain.json', 'r', encoding='utf-8')as f:
        domain_profile = json.load(f)
        domain_profile['name'] = config['config_name']
        domain_profile['server_names'] = config['server_names']
        domain_profile['backend_config']['servers'][0]['host'] = config['backend_config_host']
        domain_profile['remark'] = config['remark']
        domain_profile['is_enabled'] = config['is_enabled']
        domain_profile['ssl_cert'] = config['ssl_cert']
        
        resp = requests.post( CT_HOST + "/api/SoftwareReverseProxyWebsiteAPI", headers = HEADERS, data=json.dumps(domain_profile), verify=False)
        result = resp.json()
        err = result['err']
        if err is None:
            logging.debug(f'成功创建防护域名！ {show_text}')
            print(say())
            say(channel=channel_id, text=f'成功创建防护域名！ {show_text}')
            ack()
        else:
            logging.debug(f'创建防护域名失败！ {show_text}')
            say(channel=channel_id, text=f'创建防护域名失败！ {show_text}')
            ack()


if __name__ == "__main__":
    # export SLACK_APP_TOKEN=xapp-***
    # export SLACK_BOT_TOKEN=xoxb-***
    SocketModeHandler(app, SLACK_APP_TOKEN ).start()
