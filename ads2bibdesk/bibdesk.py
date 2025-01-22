import logging
import subprocess
import os
import time

import AppKit  # from pyobjc-framework-Cocoa
app_info = AppKit.NSBundle.mainBundle().infoDictionary()
app_info["LSBackgroundOnly"] = 1

logger = logging.getLogger(__name__)

BIBDESK_PATH = "/System/Volumes/Data/Applications/TeX/BibDesk.app"

class BibDesk(object):

    def __init__(self):
        """
        Manage BibDesk publications using AppKit
        """
        self.ensure_bibdesk_running()
        self.app = AppKit.NSAppleScript.alloc()
        self.refresh()

    def ensure_bibdesk_running(self):
        """
        Ensure BibDesk is running and accessible
        """
        try:
            # Check if BibDesk exists
            if not os.path.exists(BIBDESK_PATH):
                raise RuntimeError(f"BibDesk not found at {BIBDESK_PATH}")
            
            # Try to launch BibDesk if not running, with LSBackgroundOnly flag
            launch_cmd = '''
                tell application "System Events"
                    set isRunning to (exists (processes where name is "BibDesk"))
                    if not isRunning then
                        tell application "BibDesk"
                            launch
                            set visible of every window to false
                        end tell
                    end if
                end tell
            '''
            subprocess.run(['osascript', '-e', launch_cmd], check=True)
            
            # Give it a moment to start up
            time.sleep(2)  # Increased delay
            
            # Verify BibDesk is running
            verify_cmd = 'tell application "BibDesk" to return version'
            result = subprocess.run(['osascript', '-e', verify_cmd], 
                                   capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to verify BibDesk: {result.stderr}")
                raise RuntimeError("BibDesk verification failed")
            logger.debug(f"BibDesk version: {result.stdout.strip()}")
            
        except Exception as e:
            logger.error(f"Failed to start BibDesk: {str(e)}")
            raise

    def __call__(self, cmd, pid=None, strlist=False, error=False):
        """
        Run AppleScript command on first document of BibDesk
        :param cmd: AppleScript command string
        :param pid: address call to first/last publication of document
        :param strlist: return output as list of string
        :param error: return full output of call, including error
        """
        try:
            if pid is None:
                # First try to create a document if none exists
                init_cmd = 'tell application "BibDesk"\nif (count of documents) is 0 then\nmake new document\nend if\nend tell'
                init_result = self.app.initWithSource_(init_cmd).executeAndReturnError_(None)
                if init_result is None or init_result[0] is None:
                    logger.error("Failed to initialize BibDesk document")
                    raise RuntimeError("Failed to initialize BibDesk document")
                
                # Now execute the actual command
                cmd = f'tell application "BibDesk"\ntell first document\n{cmd}\nend tell\nend tell'
            else:
                cmd = f'tell application "BibDesk"\ntell first document\ntell first publication whose id is "{pid}"\n{cmd}\nend tell\nend tell\nend tell'
            
            logger.debug(f"Executing AppleScript command: {cmd}")
            output = self.app.initWithSource_(cmd).executeAndReturnError_(None)
            
            if output is None:
                logger.error("AppleScript execution returned None")
                raise RuntimeError("AppleScript execution failed")
            
            if len(output) < 1 or output[0] is None:
                logger.error("AppleScript execution returned no result")
                raise RuntimeError("AppleScript execution returned no result")
            
            if not error:
                output = output[0]
                if strlist:
                    if output.numberOfItems() == 0:
                        return []
                    output = [output.descriptorAtIndex_(i + 1).stringValue()
                              for i in range(output.numberOfItems())]
            return output
            
        except Exception as e:
            logger.error(f"AppleScript execution failed: {str(e)}")
            raise

    def refresh(self):
        """
        Refresh the BibDesk document state
        """
        try:
            # First ensure we have a document
            init_cmd = 'tell application "BibDesk"\nif (count of documents) is 0 then\nmake new document\nend if\nend tell'
            init_result = self.app.initWithSource_(init_cmd).executeAndReturnError_(None)
            if init_result is None or init_result[0] is None:
                logger.error("Failed to initialize BibDesk document")
                raise RuntimeError("Failed to initialize BibDesk document")
            
            # Now get publications
            self.titles = self('return title of publications', strlist=True)
            self.ids = self('return id of publications', strlist=True)
            
        except Exception as e:
            logger.error(f"Failed to refresh BibDesk state: {str(e)}")
            raise

    def pid(self, title):
        return self.ids[self.titles.index(title)]

    def authors(self, pid):
        """
        Get name of authors of publication
        """
        return self('name of authors', pid, strlist=True)

    def safe_delete(self, pid):
        """
        Safely delete publication + PDFs, taking into account
        the existence of PDFs with Skim notes
        """
        keptPDFs = []
        files = self('POSIX path of linked files', pid, strlist=True)
        notes = self('text Skim notes of linked files', pid, strlist=True)

        for f, n in zip([f for f in files if f is not None],
                        [n for n in notes if n is not None]):
            if f.lower().endswith('pdf'):
                if '_notes_' in f:
                    keptPDFs.append(f)
                else:
                    # check for annotations
                    if n or has_annotationss(f):
                        suffix = 1
                        path, ext = os.path.splitext(f)
                        backup = path + '_notes_{:d}.pdf'.format(suffix)
                        while os.path.exists(backup):
                            suffix += 1
                            backup = path + '_notes_{:d}.pdf'.format(suffix)
                        # rename
                        os.rename(f, backup)
                        keptPDFs.append(backup)
                        if os.path.exists(path + '.skim'):
                            os.rename(path + '.skim',
                                      path + '_notes_{:d}.skim'.format(suffix))
                    else:
                        # remove file
                        os.remove(f)
        # delete publication
        self('delete', pid)
        return keptPDFs

    def get_groups(self, pid):
        """
        Get names of the static groups
        return a string list
            output:      list        
        """
        cmd = """
            tell first document of application "BibDesk"
            set oldPub to ( get first publication whose id is "{}" ) 
            set pGroups to ( get static groups whose publications contains oldPub ) 
            set GroupNames to {{}}
            repeat with aGroup in pGroups 
                copy (name of aGroup) to the end of GroupNames
            end repeat
            return GroupNames 
            end tell
        """.format(pid)

        output = self.app.initWithSource_(cmd).executeAndReturnError_(None)
        output = output[0]
        output = [output.descriptorAtIndex_(i + 1).stringValue()
                  for i in range(output.numberOfItems())]
        logger.debug(
            "check static groups: pid: {}; static group: {}".format(pid, output))
        return output

    def add_groups(self, pid, groups):
        """
        add the publication into static groups
        note:
            AppleScript lists are bracked by curly braces with items separate by commas
            Each item is an alphanumeric label(?) or a string enclosed by double quotes or a list itself
                e.g. { "group1", "groups" }
            pid:         string
            groups:      list
        """
        as_groups = ", ".join(['\"'+x+'\"' for x in groups])
        cmd = """
            tell first document of application "BibDesk"
                set newPub to ( get first publication whose id is "{}" )
                #set AppleScript's text item delimiters to return
                repeat with agroup in {{ {} }}
                    set theGroup to get static group agroup
                    add newPub to theGroup
                end repeat
            end tell
        """.format(pid, as_groups)
        output = self.app.initWithSource_(cmd).executeAndReturnError_(None)
        new_groups = self.get_groups(pid)
        return new_groups


def has_annotationss(f):
    """
    """
    return subprocess.Popen(
        "strings {} | grep  -E 'Contents[ ]{{0,1}}\('".format(f),
        shell=True, stdout=subprocess.PIPE,
        stderr=open('/dev/null', 'w')).stdout.read() != b''     # b''!=u'' in Python 3
