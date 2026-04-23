"""setupstepper.py"""

from json import loads
from logging import DEBUG, basicConfig, exception, info
from ntpath import basename
from os import listdir, remove, system
from os.path import exists
from re import sub
from shutil import copy, copy2
from time import sleep
from warnings import simplefilter

from pywinauto.application import Application, WindowSpecification
from pywinauto.findbestmatch import MatchError
from pywinauto.findwindows import find_elements

# Configure logging output
basicConfig(format="%(message)s", encoding="utf-16", level=DEBUG)

# Disable warnings
simplefilter("ignore", category=UserWarning)

# Configurable Strings
DRIVE = "Z:"
UNFILTERED = "results.txt"
FILE_LIST = "files.txt"
FILE_SIGNAL = "done.txt"

# Passed in command line arguments as dictionary (flag: value)
arguments = {"-path": None, "-debug": "off", "-license": "Stepper"}

# List of controls that have elevated priority
desired = ["next", "yes", "finish", "ok", "start", "install", "complete"]
desired.extend(["full"])

# List of controls that threw an error and should not be touched
blacklisted = []


def launch_installer() -> Application:
    """Creates an application object and launches the desired installer based
    on the path supplied in the arguments. If the installer is an msi, it is
    launched with msiexec.

    Args:
        None.

    Returns:
        Application: The application object that started the installer.
    """

    # Create an application object
    app = Application()

    # Start application with proper arguments
    msiprefix = "msiexec /i " if (arguments["-type"] == "msi") else ""
    app = app.start(f'{msiprefix}"{arguments["-path"]}"')

    # Wait for the application to start
    sleep(1.5 if (arguments["-type"] == "msi") else 0.75)

    return app


def get_controls(dialog: WindowSpecification) -> list:
    """Gathers relevant controls from the given dialog and organizes their
    class, name, and ID into a sublist that will be put into the 'controls'
    list.

    Args:
        dialog (WindowSpecification): The dialog to be analyzed.

    Returns:
        list: Contains sublists that contain information about each control.
    """

    controls = []

    # Initiate list of button names that shouldn't be considered
    unwanted_controls = ["Static", "#32770", "CtrlNotifySink", "DirectUIHWND"]
    unwanted_controls.extend(["SysLink", "TNewNotebookPage", "TNewNotebook"])

    edit_number = 1

    for child in dialog.children():
        child_class = child.friendly_class_name()

        # Assign edit control numbers appropriately
        if child_class == "Edit":
            child_class += str(edit_number)
            edit_number += 1

        # Dont include a non-selectable or unwanted control
        if not child.is_enabled() or (child_class in unwanted_controls):
            continue

        # For readability, remove all special characters from non-text boxes
        name = child.texts()[0]

        if not child_class.startswith("Edit"):
            name = sub(r"^\W*|[^0-9a-zA-Z| ]+|\W*$", "", name)

        # For each control, make a sublist with Type, Text, and ID
        controls.append([child_class, name.lower(), child.control_id()])

    return controls


def get_priority_list(ctrl: list) -> list:
    """Creates a parallel list to 'ctrl' whose nth integer value represents
    the priority value of the nth control. Priority values are assigned
    based on various conditions that attempt to generalize the next best
    step that results in successful installation.

    Args:
        ctrl (list): The list of controls returned from get_controls().

    Returns:
        list: Has priority values for each control in its parallel list 'ctrl'.
    """

    num_controls = len(ctrl)
    priority = [0] * num_controls

    for i in range(num_controls):
        classname, text, control_id = ctrl[i]
        is_edit = classname.startswith("Edit")

        # Condition for license RadioButton
        license_cond = "agree" in text or "accept" in text
        license_cond = license_cond and ("not" not in text) and not is_edit

        # Condition for presence of an edit box
        edit_cond = (arguments["-license"] != text) and is_edit
        edit_cond = edit_cond and not text.startswith("c:")
        edit_cond_value = len(text)

        # Condition for control text being in the desired list
        desired_cond = text in desired

        # Condition for controls to avoid
        bad_cond = (control_id in blacklisted) or (text == "cancel")
        bad_cond = bad_cond or ((text == "") and not is_edit)

        # Assign priority value
        if bad_cond:
            priority[i] = 0
        elif edit_cond:
            priority[i] = 4 + edit_cond_value
        elif desired_cond:
            priority[i] = 3
        elif license_cond:
            priority[i] = 2
        else:
            priority[i] = 1

    return priority


def proceed(dialog: WindowSpecification, control: list, p_val: int) -> None:
    """Decides whether to interact with the control or to wait. If the
    installation has started, allow the interaction with any control to exit
    the installer that would disrupt the installation configuration beforehand.
    Buttons are clicked and Edits are scrolled and have their text changed.

    Args:
        dialog (WindowSpecification): The dialog box containing the 'controls'.
        control (list): Attributes of the control with the highest priority.
        p_val (int): The priority value of 'control'.

    Returns:
        None.
    """

    # Decide whether to wait or to advance
    classname, text, control_id = control if (p_val != 0) else ["", "", ""]

    # If a control was the culprit, add it to the blacklist
    on_trial = 0 if "next" in text else control_id
    blacklisted.append(on_trial)

    # Scroll down and change the text in the edit box to the license code
    if classname.startswith("Edit"):
        dialog[classname].scroll(direction="down", amount="end")
        dialog[classname].set_edit_text(arguments["-license"])
        blacklisted.pop()
        blacklisted.append(control_id)

    # Perform button press if we have advanced
    elif classname != "":
        dialog[text].click()
        blacklisted.pop()

        # Add exit option once an install button has been pressed
        if text in ("install", "start"):
            desired.append("exit")

    # Give the UI a chance to load controls if it hasn't
    else:
        blacklisted.pop()
        sleep(0.2)


def step_through(app: Application) -> None:
    """The main loop that sorts the controls from the current dialog and steps
    through the installer. If the '-debug' flag is on, the list of controls are
    dumped in descending order of priority and the user can determine whether
    the next step is done manually or not.

    Args:
        app (Application): The Application object that started the installer.

    Returns:
        None.
    """

    controls = None

    while app.is_process_running():
        try:
            # Get dialog box and retry if none are found
            window = app.top_window().texts()[0]

            if window == "":
                continue

            dialog = app[window]

            # Get controls and sort them. Retry if no controls are found
            controls = get_controls(dialog)
            p_l = get_priority_list(controls)

            if len(p_l) == 0:
                continue

            p_l, controls = (
                list(t) for t in zip(*sorted(zip(p_l, controls, strict=False)), strict=False)
            )
            p_l.reverse()
            controls.reverse()

            # Print controls in debug mode
            auto_step = ""

            if arguments["-debug"] == "on":
                info("Controls for: " + window)
                info("--------------------------------")

                for control in controls:
                    info(f"> {control[0]: <15} {control[1]: <15}")

                auto_step = input("\nENTER to step or type to manually step:")
                info("")

            # Decide what to press next if debug mode allowed it
            if len(auto_step) == 0:
                proceed(dialog, controls[0], p_l[0])

        except (RuntimeError, MatchError, TimeoutError) as err:
            # If a new process has been spawned, latch on to that one instead
            if str(err) == "No windows for that process could be found":
                # Indicates that the installer has unexpectedly terminated
                if controls is not None:
                    break

                info("Ensure that the installer is in focus.")

                if arguments["-debug"] == "on":
                    info(find_elements(active_only=True))

                # Best way to generally latch on to multiprocess installers
                app.connect(active_only=True, found_index=0)
                continue

            exception(f"Error: {err}")

    info("Installer has terminated.")


def handle_transfers() -> None:
    """Read the list of files that the host machine wants and attempt to
    transfer them into the shared folder. 'done.txt' signals to the host
    that all of the files have been acknowledged.

    Args:
        None.

    Returns:
        None.
    """

    # Copy each file into the shared folder
    with open(f"{DRIVE}/{FILE_LIST}", encoding="utf-8") as f_handle:
        for line in f_handle.readlines():
            # The name for each file is changed to a variant of its path
            file = line.strip()
            newname = file[3:].replace("/", "!SEP!")

            try:
                copy2(file, f"{DRIVE}/{newname}")
            except OSError as err:
                exception(err)

    # Signal to the host that each file has finished copying
    with open(FILE_SIGNAL, "w", encoding="utf-8") as f_handle:
        f_handle.write("done")

    copy(FILE_SIGNAL, f"{DRIVE}/{FILE_SIGNAL}")
    remove(FILE_SIGNAL)

    # "Sleep" until the host has finished processing files
    while exists(f"{DRIVE}/{FILE_SIGNAL}"):
        sleep(0.5)


def handle_file(fname: str) -> None:
    """If the file is a txt, it's assumed to be the arguments for the file
    that will be placed into the folder next, which it will run and step
    through. Finally, the file is deleted from the folder. The installer
    is meant to be copied (not moved) into the directory.

    Args:
        fname (str): The name of the file to inspect

    Returns:
        None.
    """

    if arguments["-debug"] == "on":
        info(f"file: {fname}")

    # Handle file transfers
    if basename(fname) == FILE_LIST:
        handle_transfers()
        return

    # Handle installer file
    if fname[-3:] != "txt":
        arguments["-path"] = fname

        try:
            # Open and execute the installer
            app = launch_installer()
            step_through(app)

            # Stop capturing output after a bit
            sleep(10)
            system("taskkill /f /im minifilter.exe")

            # Move results into the shared folder and cleanup
            remove(fname)
            sleep(5)
            copy(UNFILTERED, f"{DRIVE}/{UNFILTERED}")
            remove(UNFILTERED)

            # Wait for results.txt to transfer
            while exists(f"{DRIVE}/{UNFILTERED}"):
                sleep(0.5)

            info(f"{UNFILTERED} file move complete")
        except OSError as err:
            exception(err)
            sleep(0.5)

        return

    # Parse txt into dict as json
    try:
        info("Processing text file as args...")
        with open(fname, encoding="utf-8") as f_handle:
            argstr = f_handle.readlines()[0]
            arguments.update(loads(argstr))

        # Remove file from folder
        remove(fname)
    except OSError as err:
        exception(err)
        sleep(0.5)


def main() -> None:
    """Continously checks to see if any new file has been added to the shared
    folder. If it has, it passes the file path to the handler. This script is
    meant to always run on a windows VM with admin privileges.

    Args:
        None.

    Returns:
        None.
    """

    while True:
        # Retry if the shared folder doesn't exist
        if not exists(f"{DRIVE}/"):
            continue

        try:
            # Check for any files in the shared folder
            files = listdir(f"{DRIVE}/")

            if len(files) == 0:
                continue

            handle_file(f"{DRIVE}/{files[0]}")
        except OSError as err:
            exception(err)


if __name__ == "__main__":
    main()
