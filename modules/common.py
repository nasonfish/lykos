# The bot commands implemented in here are present no matter which module is loaded

import botconfig
from tools import decorators
import logging
import tools.moduleloader as ld
import traceback
from settings import common as var
from base64 import b64encode
import imp
import settings.wolfgame as settings
import modules.wolfgame as default
import sys
import os
from oyoyo.parse import parse_nick

settings.ERRORS = 0
settings.AUTO_OP_FLAG = False
settings.AUTO_OP_FAIL = False

def on_privmsg(cli, rawnick, chan, msg, notice = False):
    currmod = ld.MODULES[ld.CURRENT_MODULE]
    nick,u,m,h = parse_nick(raw_nick)
    
    if botconfig.IGNORE_HIDDEN_COMMANDS and (chan.startswith("@#") or chan.startswith("+#")):
        return
    
    if (notice and ((chan != botconfig.NICK and not botconfig.ALLOW_NOTICE_COMMANDS) or
                    (chan == botconfig.NICK and not botconfig.ALLOW_PRIVATE_NOTICE_COMMANDS))
                    and "NickServ" != nick):
        return  # not allowed in settings
           
    if chan != botconfig.NICK:  #not a PM
        if currmod and "" in currmod.COMMANDS.keys():
            for fn in currmod.COMMANDS[""]:
                try:
                    fn(cli, rawnick, chan, msg)
                except Exception as e:
                    if botconfig.DEBUG_MODE:
                        raise e
                    else:
                        logging.error(traceback.format_exc())
                        cli.msg(chan, "An error has occurred and has been logged.")
                        if botconfig.SPECIAL_CHAN != "":
                            cli.msg(botconfig.SPECIAL_CHAN, traceback.format_exc())
                        settings.ERRORS += 1
                        if settings.ERRORS == settings.MAX_ERRORS:
                            cli.quit("An error has been encountered")
            # Now that is always called first.
        for x in set(list(COMMANDS.keys()) + (list(currmod.COMMANDS.keys()) if currmod else list())):
            if x and msg.lower().startswith(botconfig.CMD_CHAR+x) and x not in botconfig.DISABLED_COMMANDS:
                h = msg[len(x)+1:]
                if not h or h[0] == " " or not x:
                    for fn in COMMANDS.get(x,[])+(currmod.COMMANDS.get(x,[]) if currmod else []):
                        try:
                            fn(cli, rawnick, chan, h.lstrip())
                        except Exception as e:
                            if botconfig.DEBUG_MODE:
                                raise e
                            else:
                                logging.error(traceback.format_exc())
                                cli.msg(chan, "An error has occurred and has been logged.")
                                if botconfig.SPECIAL_CHAN != "":
                                    cli.msg(botconfig.SPECIAL_CHAN, traceback.format_exc())
                                settings.ERRORS += 1
                                if settings.ERRORS == settings.MAX_ERRORS:
            
    else:
        for x in set(list(PM_COMMANDS.keys()) + (list(currmod.PM_COMMANDS.keys()) if currmod else list())):
            if msg.lower().startswith(botconfig.CMD_CHAR+x):
                h = msg[len(x)+1:]
            elif not x or msg.lower().startswith(x):
                h = msg[len(x):]
            else:
                continue
            if not h or h[0] == " " or not x:
                for fn in PM_COMMANDS.get(x, [])+(currmod.PM_COMMANDS.get(x,[]) if currmod else []):
                    try:
                        fn(cli, rawnick, h.lstrip())
                    except Exception as e:
                        if botconfig.DEBUG_MODE:
                            raise e
                        else:
                            logging.error(traceback.format_exc())
                            cli.msg(chan, "An error has occurred and has been logged.")
                            if botconfig.SPECIAL_CHAN != "":
                                cli.msg(botconfig.SPECIAL_CHAN, traceback.format_exc())
                            settings.ERRORS += 1
                            if settings.ERRORS == settings.MAX_ERRORS:
                                cli.quit("An error has been encountered")
    
def __unhandled__(cli, prefix, cmd, *args):
    currmod = ld.MODULES[ld.CURRENT_MODULE]

    if cmd in set(list(HOOKS.keys())+(list(currmod.HOOKS.keys()) if currmod else list())):
        largs = list(args)
        for i,arg in enumerate(largs):
            if isinstance(arg, bytes): largs[i] = arg.decode('ascii')
        for fn in HOOKS.get(cmd, [])+(currmod.HOOKS.get(cmd, []) if currmod else []):
            try:
                fn(cli, prefix, *largs)
            except Exception as e:
                if botconfig.DEBUG_MODE:
                    raise e
                else:
                    logging.error(traceback.format_exc())
                    cli.msg(botconfig.CHANNEL, "An error has occurred and has been logged.")
                    if botconfig.SPECIAL_CHAN != "":
                        cli.msg(botconfig.SPECIAL_CHAN, traceback.format_exc())
                    settings.ERRORS += 1
                    if settings.ERRORS == settings.MAX_ERRORS:
                        cli.quit("An error has been encountered")
    else:
        logging.debug('Unhandled command {0}({1})'.format(cmd, [arg.decode('utf_8')
                                                              for arg in args
                                                              if isinstance(arg, bytes)]))

    
COMMANDS = {}
PM_COMMANDS = {}
HOOKS = {}

cmd = decorators.generate(COMMANDS)
pmcmd = decorators.generate(PM_COMMANDS)
hook = decorators.generate(HOOKS, raw_nick=True, permissions=False)

@hook("error")
def restart_on_quit(cli, prefix, msg):
    print("RESTARTING")
    python = sys.executable
    os.execl(python, python, *sys.argv)
    
@pmcmd("access")
def check_flags(cli, nick, rest):
    if nick == "NickServ":
        for botconfig.CHANNEL in rest:
            if 'O' in rest:
                settings.AUTO_OP_FLAG = True
                return
            if 'O' not in rest and 'o' not in rest:
                settings.AUTO_OP_FAIL = True
                return

def connect_callback(cli):

    def send_listchans(*args):
        if botconfig.PASS:
            cli.msg("NickServ", "listchans")

    def prepare_stuff(*args):
        cli.join(botconfig.CHANNEL)
        if settings.AUTO_OP_FLAG == False and not settings.AUTO_OP_FAIL:
            cli.msg("ChanServ", "op "+botconfig.CHANNEL)
        if settings.LOG_CHAN == True or settings.MINIMALIST_LOG == True:
            cli.join(botconfig.ADMIN_CHAN)
            chan = botconfig.ADMIN_CHAN
        if settings.LOG_CHAN == False and settings.MINIMALIST_LOG == False:
            chan = botconfig.CHANNEL
        if botconfig.SPECIAL_CHAN != "":
            cli.join(botconfig.SPECIAL_CHAN)
            chan = botconfig.SPECIAL_CHAN
        if settings.AUTO_OP_FAIL == True and botconfig.OP_NEEDED == True:
            cli.msg(chan, "\u0002Error\u0002: OP status is needed for the game to work.")
        if settings.RAW_JOIN == True and botconfig.ALT_CHANS != "":
            cli.join(botconfig.ALT_CHANS)
        if botconfig.PERFORM != "":
            cli.send(botconfig.PERFORM)
        if botconfig.ADMIN_CHAN == "":
            settings.LOG_CHAN = False
            settings.MINIMALIST_LOG = False
        if botconfig.DEV_CHAN != "" and settings.ALLOW_GIT == True:
            cli.join(botconfig.DEV_CHAN)
        
        cli.cap("REQ", "extended-join")
        cli.cap("REQ", "account-notify")
        
        try:
            ld.MODULES[ld.CURRENT_MODULE].connect_callback(cli)
        except AttributeError:
            pass # no connect_callback for this one
        
        cli.nick(botconfig.NICK)  # very important (for regain/release)
        
    prepare_stuff = hook("endofmotd", hookid=294)(prepare_stuff)

    def mustregain(cli, *blah):
        if not botconfig.PASS:
            return
        if settings.NS_GHOST:
            cli.ns_ghost()
            cli.nick(botconfig.NICK)
        else:
            cli.ns_regain()                    
                    
    def mustrelease(cli, *rest):
        if not botconfig.PASS:
            return # prevents the bot from trying to release without a password
        cli.ns_release()
        cli.nick(botconfig.NICK)

    @hook("unavailresource", hookid=239)
    @hook("nicknameinuse", hookid=239)
    def must_use_temp_nick(cli, *etc):
        cli.nick(botconfig.NICK+"_")
        cli.user(botconfig.NICK, "")
        
        decorators.unhook(HOOKS, 239)
        hook("unavailresource")(mustrelease)
        hook("nicknameinuse")(mustregain)
        
    if botconfig.SASL_AUTHENTICATION:
    
        @hook("authenticate")
        def auth_plus(cli, something, plus):
            if plus == "+":
                nick_b = bytes(botconfig.USERNAME if botconfig.USERNAME else botconfig.NICK, "utf-8")
                pass_b = bytes(botconfig.PASS, "utf-8")
                secrt_msg = b'\0'.join((nick_b, nick_b, pass_b))
                cli.send("AUTHENTICATE " + b64encode(secrt_msg).decode("utf-8"))
    
        @hook("cap")
        def on_cap(cli, svr, mynick, ack, cap):
            if ack.upper() == "ACK" and "sasl" in cap:
                cli.send("AUTHENTICATE PLAIN")
                
        @hook("903")
        def on_successful_auth(cli, blah, blahh, blahhh):
            cli.cap("END")
            
        @hook("904")
        @hook("905")
        @hook("906")
        @hook("907")
        def on_failure_auth(cli, *etc):
            cli.quit()
            print("Authentication failed.  Did you fill the account name "+
                  "in botconfig.USERNAME if it's different from the bot nick?")
               
        
        
@hook("ping")
def on_ping(cli, prefix, server):
    cli.send('PONG', server)
    
    

if botconfig.DEBUG_MODE:
    @cmd("module", admin_only = True)
    def ch_module(cli, nick, chan, rest):
        rest = rest.strip()
        if rest in ld.MODULES.keys():
            ld.CURRENT_MODULE = rest
            ld.MODULES[rest].connect_callback(cli)
            cli.msg(chan, "Module {0} is now active.".format(rest))
        else:
            cli.msg(chan, "Module {0} does not exist.".format(rest))

## Logging, op, admin and owner handling

@hook("join")
def join(cli, nick, *chan):
    chan = list(chan)
    if settings.LOG_CHAN == True and botconfig.ADMIN_CHAN != "":
        cli.msg(botconfig.ADMIN_CHAN, "processCommand (b'{0}')join({1})".format(nick, chan))
    if nick in settings.IS_ADMIN and settings.AUTO_LOG_TOGGLE == True and settings.LOG_CHAN == False:
        settings.LOG_CHAN = True
        cli.msg(chan, "Auto-logging has been enabled.")
    if nick == botconfig.NICK and chan == botconfig.ADMIN_CHAN:
        settings.TOGGLE_ENABLED = False
        cli.who(botconfig.ADMIN_CHAN, "%nuchaf")
        @hook("whospcrpl", hookid=652)
        def log_toggle_join(cli, server, me, chan, ident, host, nick, status, account):
            if nick in settings.IS_ADMIN and settings.IS_ADMIN[nick] == True and chan == botconfig.ADMIN_CHAN:
                settings.TOGGLE_ENABLED = True
        @hook("endofwho", hookid=652)
        def toggle_check_join(*stuff):
            if not settings.TOGGLE_ENABLED:
                settings.LOG_CHAN = False
            decorators.unhook(HOOKS, 652)

@hook("part")
def part(cli, nick, *chan):
    chan = list(chan)
    if settings.LOG_CHAN == True and botconfig.ADMIN_CHAN != "":
        cli.msg(botconfig.ADMIN_CHAN, "processCommand (b'{0}')part({1})".format(nick, chan))
        if settings.AUTO_LOG_TOGGLE == True:
            settings.DISABLE_AUTO_LOG = True
            cli.who(botconfig.ADMIN_CHAN, "%nuchaf")
            @hook("whospcrpl", hookid=652)
            def log_toggle_part(cli, server, me, chan, ident, host, nick, status, account):
                if nick in settings.IS_ADMIN and chan == botconfig.ADMIN_CHAN:
                    settings.DISABLE_AUTO_LOG = False
            @hook("endofwho", hookid=652)
            def toggle_check_part(*stuff):
                if settings.DISABLE_AUTO_LOG == True:
                    settings.LOG_CHAN = False
                decorators.unhook(HOOKS, 652)
    if nick in settings.IS_OP and chan == botconfig.CHANNEL:
        settings.IS_OP.remove(nick)
    if nick in settings.WAS_OP and chan == botconfig.CHANNEL:
        settings.WAS_OP.remove(nick)
    if nick in settings.IS_ADMIN and chan == botconfig.CHANNEL:
        settings.IS_ADMIN.remove(nick)
    if nick in settings.IS_OWNER and chan == botconfig.CHANNEL:
        settings.IS_OWNER.remove(nick)

@hook("kick")
def kick(cli, nick, *rest): # cli, nick, chan, target, reason
    rest = list(rest)
    if settings.LOG_CHAN == True and botconfig.ADMIN_CHAN != "":
        cli.msg(botconfig.ADMIN_CHAN, "processCommand (b'{0}')kick({1})".format(nick, rest))
        if settings.AUTO_LOG_TOGGLE == True:
            settings.DISABLE_AUTO_LOG = True
            cli.who(botconfig.ADMIN_CHAN, "%nuchaf")
            @hook("whospcrpl", hookid=652)
            def log_toggle_kick(cli, server, me, chan, ident, host, nick, status, account):
                if nick in settings.IS_ADMIN and settings.IS_ADMIN[nick] == True and chan == botconfig.ADMIN_CHAN:
                    settings.DISABLE_AUTO_LOG = False
            @hook("endofwho", hookid=652)
            def toggle_check_kick(*stuff):
                if settings.DISABLE_AUTO_LOG == True:
                    settings.LOG_CHAN = False
                decorators.unhook(HOOKS, 652)
    if nick in settings.IS_OP and chan == botconfig.CHANNEL:
        settings.IS_OP.remove(nick)
    if nick in settings.WAS_OP and chan == botconfig.CHANNEL:
        settings.WAS_OP.remove(nick)
