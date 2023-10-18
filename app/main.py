import re
import secrets
import subprocess
from typing import Union

from fastapi import FastAPI, status, Request
from fastapi.responses import JSONResponse

from app.model import User, ResponseOutput, Command
from app.rc_handler import return_codes

app = FastAPI(
    title="HTTP POST request to GAM executor",
    summary="Translates HTTP requests into GAM commands and executes them.",
    version='0.0.1',
    contact={
        "name": "Bayzat SRE Team",
        "url": "https://www.bayzat.com",
        "email": "sre@bayzat.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
)


class GamException(Exception):
    def __init__(self, rc, cmd, stderr):
        self.rc = rc
        self.rc_desc = return_codes[rc]
        self.cmd = cmd
        self.stderr = stderr


@app.exception_handler(GamException)
async def gam_exception_handler(request: Request, exc: GamException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"rc": exc.rc, "command": exc.cmd, "rc_description": exc.rc_desc, "stderr": exc.stderr}
    )


def command_executor(cmd: Union[list[list[str]], list[str]]) -> dict:
    output = []
    if isinstance(cmd[0], list):
        for c in cmd:
            c = ['gam'] + c
            p = subprocess.Popen(c, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode == 0:
                output.append({'command': c, 'stdout': out.decode('utf-8')})
            else:
                raise GamException(rc=p.returncode, cmd=c, stderr=err.decode('utf-8'))

    else:
        cmd = ['gam'] + cmd
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode == 0:
            output.append({'command': cmd, 'stdout': out.decode('utf-8')})
        else:
            raise GamException(rc=p.returncode, cmd=cmd, stderr=err.decode('utf-8'))
    return {"output": output}


@app.post('/redirect-mail', response_model=ResponseOutput,
          description="Adds email redirection from one user to another")
def redirect_email(user: User):
    cmds = [
        ['user', user.email, 'add', 'forwardingaddress', user.redirect_to],
        ['user', user.email, 'forward', 'on', 'keep', user.redirect_to]
    ]
    return command_executor(cmds)


def info_parser(output: str) -> dict:
    split = output.split('\n')
    current_key = "general"
    parsed = {current_key: {}}
    for line in split:
        kv = line.strip().split(':', 1)
        if len(kv) == 2 and not kv[1]:
            current_key = kv[0].lower()
            parsed.update({current_key: {}})
        elif len(kv) == 2 and kv[0] == "Groups":
            current_key = kv[0].lower()
            parsed.update({current_key: {}})
        elif len(kv) == 2 and kv[0] == "Licenses":
            continue
        elif len(kv) == 2 and kv[0] and kv[1]:
            parsed[current_key].update({kv[0]: kv[1]})
    return parsed


@app.post('/info', response_model=ResponseOutput,
          description="Returns information about user")
def info(user: User):
    cmd = ['info', 'user', user.email]
    return command_executor(cmd)


@app.post('/reset-password', response_model=ResponseOutput,
          description="Resets user password and sets it to random")
def reset_password(user: User):
    password = secrets.token_urlsafe(15)
    cmds = [
        ['update', 'user', user.email, 'password', password],
        ['update', 'user', user.email, 'changepassword', 'on'],
        ['update', 'user', user.email, 'changepassword', 'off'],
    ]
    output = command_executor(cmds)
    output.update({"password": password})
    return output


def parse_backup_codes(stdout: str):
    pattern = re.compile(r"(\d{1,2}: \d{8})", re.MULTILINE)
    return pattern.findall(stdout)


@app.post('/reset-token', response_model=ResponseOutput,
          description="Removes all backup codes and active tokens for user")
def reset_token(user: User):
    cmds = [
        ['user', user.email, 'deprovision'],
        ['user', user.email, 'update', 'backupcodes'],
    ]
    output = command_executor(cmds)
    backup_codes = parse_backup_codes(output["output"][1]["stdout"])
    output.update({"backup_codes": backup_codes})
    return output


@app.post('/disable-user-mailing', response_model=ResponseOutput,
          description="Disables all IMAP, POP, FORWARD and GAL for specified user")
def disable_user_mailing(user: User):
    cmds = [
        ['user', user.email, 'forward', 'off'],
        ['user', user.email, 'imap', 'off'],
        ['user', user.email, 'pop', 'off'],
        ['user', user.email, 'gal', 'off'],
    ]
    return command_executor(cmds)


@app.post('/remove-groups', response_model=ResponseOutput,
          description="Removes user from all groups")
def remove_groups(user: User):
    cmd = ['info', 'user', user.email]
    output = command_executor(cmd)
    user_info = info_parser(output['output'][0]['stdout'])
    cmds = []
    for k, v in user_info['groups'].items():
        cmds.append(['update', 'group', v, 'remove', 'member', user.email])
    return command_executor(cmds)


# @app.post('/remove-delegates', )
# def remove_delegates(user: User):
#     command ='user', user.email, 'delete', 'delegate', delegate]
#     return command_executor(command)


@app.post('/disable-2fa', response_model=ResponseOutput,
          description="Disables 2FA for specified user")
def disable_2fa(user: User):
    cmd = ['user', user.email, 'turnoff2sv']
    return command_executor(cmd)


@app.post('/remove-recovery', response_model=ResponseOutput,
          description="Removes user recovery data - phone and alt. mail")
def remove_recovery(user: User):
    cmds = [
        ['user', user.email, 'recoveryemail', ''],
        ['user', user.email, 'recoveryphone', ''],
    ]
    return command_executor(cmds)


@app.post('/archive/{action}', response_model=ResponseOutput,
          description="Attaches Archived/Normal License to the user")
def archive(user: User, action: str = "on"):
    cmd = ['update', 'user', user.email, 'archived', action]
    return command_executor(cmd)


@app.post('/suspend/{action}', response_model=ResponseOutput,
          description="Suspends/Activates user")
def suspend(user: User, action: str = "on"):
    cmd = ['update', 'user', user.email, 'suspended', action]
    return command_executor(cmd)


@app.post('/move-user', response_model=ResponseOutput,
          description="Moves user to specified OU")
def move_user(user: User):
    cmd = ['update', 'ou', user.dest_ou, 'move', user.email]
    return command_executor(cmd)


@app.post('/command', response_model=ResponseOutput,
          description="Runs any GAM command")
def command(cmd: Command):
    return command_executor(cmd.command)
