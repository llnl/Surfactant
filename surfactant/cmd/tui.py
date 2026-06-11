# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import pathlib

import click
import textual.app
import textual.containers
import textual.css.query
import textual.events
import textual.screen
import textual.widgets
import textual.widgets.button

import surfactant.cmd.generate
import surfactant.cmd.merge
import surfactant.configmanager
import surfactant.utils.get_plugin_settings


class InfoScreen(textual.screen.Screen[None]):
    """Screen that shows text with an "OK" button"""

    def __init__(self, text: str):
        super().__init__()
        self.text = text

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Static(self.text)
        yield textual.widgets.Button("OK", id="ok")

    @textual.on(textual.widgets.Button.Pressed, "#ok")
    def handle_ok(self) -> None:
        self.dismiss()


class YesNoScreen(textual.screen.Screen[bool]):
    """Screen that presents a yes/no question"""

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Static(self.question)
        yield textual.widgets.Button("Yes", id="yes", variant="success")
        yield textual.widgets.Button("No", id="no")

    @textual.on(textual.widgets.Button.Pressed, "#yes")
    def handle_yes(self) -> None:
        self.dismiss(True)

    @textual.on(textual.widgets.Button.Pressed, "#no")
    def handle_no(self) -> None:
        self.dismiss(False)


class SelectFileButtons(textual.widgets.Static):
    # pylint: disable=too-few-public-methods
    def __init__(self, allow_folder_selection: bool):
        super().__init__()
        self.allow_folder_selection = allow_folder_selection

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Go up a directory", id="up_dir")
        if self.allow_folder_selection:
            yield textual.widgets.Button("Select directory", id="select_dir")


class SelectFile(textual.screen.ModalScreen[textual.widgets.DirectoryTree.FileSelected | None]):
    """Pop-up to select a file"""

    def __init__(self, allow_folder_selection: bool, start_path: pathlib.Path):
        super().__init__()
        self.allow_folder_selection = allow_folder_selection
        self.dir_selected: pathlib.Path = start_path

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DirectoryTree(self.dir_selected, id="file_dir")
        yield SelectFileButtons(self.allow_folder_selection)

    @textual.on(textual.widgets.Button.Pressed, "#up_dir")
    def handle_up_dir(self):
        tree = self.get_child_by_id("file_dir", textual.widgets.DirectoryTree)
        tree.path = tree.path.parent.resolve()
        tree.reload()

    @textual.on(textual.widgets.Button.Pressed, "#select_dir")
    def handle_select_dir(self):
        self.dismiss(self.dir_selected)

    def on_directory_tree_directory_selected(
        self, path: textual.widgets.DirectoryTree.DirectorySelected
    ) -> None:
        self.dir_selected = path.path

    def on_directory_tree_file_selected(
        self, path: textual.widgets.DirectoryTree.FileSelected
    ) -> None:
        self.dismiss(path.path)

    def on_key(self, event: textual.events.Key):
        if event.key == "escape":
            self.dismiss(None)


class FileInput(textual.widgets.Static):
    def __init__(
        self, label: str, allow_folder_selection: bool, file_input: textual.widgets.Input | None
    ):
        super().__init__()
        self.label = label
        self.file_input = file_input
        self.allow_folder_selection = allow_folder_selection
        self.input_path: pathlib.Path | None = None

    def compose(self) -> textual.app.ComposeResult:
        if not self.input_path:
            yield textual.widgets.Label(f"{self.label} \\[Click to set]")
        else:
            yield textual.widgets.Label(f"{self.label} {self.input_path}")

    def on_click(self):
        def set_path(path: pathlib.Path | None):
            if path:
                if self.file_input and not path.is_dir():
                    # Set the directory and the file separately
                    self.input_path = path.parent
                    self.file_input.value = path.name
                else:
                    # Just set the path
                    self.input_path = path
                self.query_one(textual.widgets.Label).update(f"{self.label} {self.input_path}")

        base_dir = pathlib.Path("./")
        if not base_dir and pathlib.Path(self.input_path).is_file():
            base_dir = self.input_path.parent
        self.app.push_screen(SelectFile(self.allow_folder_selection, base_dir), set_path)


# pylint: disable-next=too-many-instance-attributes
class GenerateTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.specimen_context = FileInput("Specimen context:", True, None)
        self.output_name = textual.widgets.Input(placeholder="Output Filename")
        self.output_dir = FileInput("Output directory:", True, self.output_name)
        self.input_sbom = FileInput("Input SBOM:", False, None)
        self.skip_gather = textual.widgets.Checkbox("Skip Gather")
        self.skip_relationships = textual.widgets.Checkbox("Skip Relationships")
        self.input_format = textual.widgets.Select([("CyTRICS", "CyTRICS")], allow_blank=False)
        self.skip_install_path = textual.widgets.Checkbox("Skip Install Path")
        self.author_name = textual.widgets.Input(placeholder="Author Name")
        self.author_type = textual.widgets.Input(placeholder="Author Type")
        self.output_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )

    def compose(self) -> textual.app.ComposeResult:
        yield self.specimen_context
        yield self.output_dir
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Filename: "), self.output_name
        )
        yield textual.widgets.Rule()
        yield textual.widgets.Label("Optional options:")
        yield self.input_sbom
        yield self.skip_gather
        yield self.skip_relationships
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Input Format: "), self.input_format
        )
        yield self.skip_install_path
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Author Name: "), self.author_name
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Author Type: "), self.author_type
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Format: "), self.output_format
        )
        yield textual.widgets.Button("Run", id="run")

    @textual.on(textual.widgets.Button.Pressed, "#run")
    def handle_run(self) -> None:
        if not self.specimen_context.input_path:
            self.app.notify("No input file selected")
            return
        if not self.output_dir.input_path:
            self.app.notify("No output directory selected")
            return
        if not self.output_name.value:
            self.app.notify("No output name supplied")
            return
        args = [
            str(self.specimen_context.input_path),
            str(self.output_dir.input_path/self.output_name.value),
        ]
        if self.input_sbom.input_path:
            args.append(self.input_sbom.input_path)
        if self.skip_gather.value:
            args.append("--skip_gather")
        if self.skip_relationships.value:
            args.append("--skip_relationships")
        if self.input_format.value:
            args.append("--input_format")
            args.append(self.input_format.value)
        if self.skip_install_path.value:
            args.append("--skip_install_path")
        author_name = self.author_name.value.strip()
        author_type = self.author_type.value.strip()
        if author_name or author_type:
            if not author_name or not author_type:
                self.app.notify("Author name and author type must both be supplied")
                return
            args.append("--author_name")
            args.append(author_name)
            args.append("--author_type")
            args.append(author_type)
        args.append("--input_format")
        args.append(self.input_format.value)
        args.append("--output_format")
        args.append(self.output_format.value)
        # Suspend is not supported in headless mode
        if not self.app.is_headless:
            with self.app.suspend():
                # pylint: disable-next=no-value-for-parameter
                surfactant.cmd.generate.sbom(args, standalone_mode=False)
                print("Press enter to continue")
                _ = input()
        else:
            # pylint: disable-next=no-value-for-parameter
            surfactant.cmd.generate.sbom(args, standalone_mode=False)
        self.app.refresh()


class InputPath(textual.widgets.Static):
    def __init__(self, desc="Input file:", allow_dir_selection=False):
        super().__init__()
        self.path_selector = FileInput(desc, allow_dir_selection, None)
        self.active = True

    def compose(self) -> textual.app.ComposeResult:
        yield textual.containers.HorizontalGroup(
            textual.widgets.Button("-", id="remove_path"), self.path_selector
        )

    @textual.on(textual.widgets.Button.Pressed, "#remove_path")
    def remove_path(self):
        self.active = False
        self.remove()


class InputPathsHolder(textual.widgets.Static):
    def __init__(self, prompt="Input file:", allow_dir_selection=False):
        super().__init__()
        self.input_paths: list[InputPath] = []
        self.prompt = prompt
        self.allow_dir_selection = allow_dir_selection

    def compose(self) -> textual.app.ComposeResult:
        for m_path in self.input_paths:
            if m_path.active:
                yield textual.containers.HorizontalGroup(textual.widgets.Label("   "), m_path)
        yield textual.widgets.Button("+", id="add_input_path")

    @textual.on(textual.widgets.Button.Pressed, "#add_input_path")
    def add_input_path(self):
        self.input_paths.append(InputPath(self.prompt, self.allow_dir_selection))
        self.mount(self.input_paths[-1], before="#add_input_path")

    def add_path(self, path: pathlib.Path):
        self.input_paths.append(InputPath(self.prompt, self.allow_dir_selection))
        self.input_paths[-1].path_selector.input_path = path


class MergeTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.merge_paths = InputPathsHolder()
        self.output_name = textual.widgets.Input(placeholder="Output Filename")
        self.output_dir = FileInput("Output directory:", True, self.output_name)
        self.input_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )
        self.output_format = textual.widgets.Select(
            [("CyTRICS", "CyTRICS"), ("SPDX", "SPDX"), ("CSV", "CSV")], allow_blank=False
        )
        self.config_file = FileInput("Config File:", False, None)
        self.btn = textual.widgets.Button("Run", id="run")

    def compose(self) -> textual.app.ComposeResult:
        yield self.merge_paths
        yield self.output_dir
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Filename: "), self.output_name
        )
        yield textual.widgets.Rule()
        yield textual.widgets.Label("Optional options:")
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Input Format: "), self.input_format
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Output Format: "), self.output_format
        )
        yield self.config_file
        yield self.btn

    @textual.on(textual.widgets.Button.Pressed, "#run")
    def handle_run(self):
        args = []
        if not self.merge_paths.input_paths:
            self.app.notify("No inputs given")
            return
        if not self.output_dir.input_path:
            self.app.notify("No output directory given")
            return
        if not self.output_name.value:
            self.app.notify("No output filename given")
            return
        for m_path in self.merge_paths.input_paths:
            if m_path.active:
                path = m_path.path_selector.input_path
                if not path:
                    self.app.notify("One or more inputs not given")
                    return
                args.append(str(path))
        args.append(str(self.output_dir.input_path/self.output_name.value))
        args.append("--input_format")
        args.append(self.input_format.value)
        args.append("--output_format")
        args.append(self.output_format.value)
        config = self.config_file.input_path
        if config:
            args.append("--config_file")
            args.append(str(config))
        # Suspend is not supported in headless mode
        if not self.app.is_headless:
            with self.app.suspend():
                # pylint: disable-next=no-value-for-parameter
                surfactant.cmd.merge.merge_command(args, standalone_mode=False)
                print("Press enter to continue")
                _ = input()
        else:
            # pylint: disable-next=no-value-for-parameter
            surfactant.cmd.merge.merge_command(args, standalone_mode=False)
        self.app.refresh()


class ContextEntry(textual.widgets.Static):
    def __init__(self, header_num):
        super().__init__()
        self.active = True
        self.border_title = str(header_num)
        self.archive = FileInput("Archive:", False, None)
        self.install_prefix = textual.widgets.Input(placeholder="Install Prefix")
        self.container_prefix = textual.widgets.Input(placeholder="Container Prefix")
        self.extract_paths = InputPathsHolder("[Click to set extract path]", True)

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Button("Delete this entry", id="delete_entry")
        yield self.archive
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Install Prefix: "), self.install_prefix
        )
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Container Prefix: "), self.container_prefix
        )
        yield textual.widgets.Label("Extract Paths:")
        yield self.extract_paths

    @textual.on(textual.widgets.Button.Pressed, "#delete_entry")
    def delete_entry(self):
        def delete_self(do_it: bool | None):
            if do_it:
                self.remove()
                self.active = False

        self.app.push_screen(
            YesNoScreen("Are you sure you want to delete this entry?"), delete_self
        )


class ContextTab(textual.widgets.Static):
    def __init__(self):
        super().__init__()
        self.context_name = textual.widgets.Input(placeholder="Context filename")
        self.context_input = FileInput("Context file directory:", True, self.context_name)
        self.context_entries: list[ContextEntry] = []
        self.context_count = 1
        self.save_btn = textual.widgets.Button("Save", id="save")
        self.load_btn = textual.widgets.Button("Load", id="load")

    def compose(self) -> textual.app.ComposeResult:
        yield self.context_input
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label("Context filename: "), self.context_name
        )
        yield textual.containers.HorizontalGroup(
            self.save_btn,
            textual.widgets.Label("   "),
            self.load_btn,
        )
        yield textual.widgets.Rule()
        yield from self.context_entries
        yield textual.widgets.Button("+", id="add_context_entry")

    @textual.on(textual.widgets.Button.Pressed, "#add_context_entry")
    def add_context_entry(self):
        self.context_entries.append(ContextEntry(self.context_count))
        self.mount(self.context_entries[-1], before="#add_context_entry")
        self.context_count += 1

    @textual.on(textual.widgets.Button.Pressed, "#save")
    def save(self):
        if not self.context_input.input_path:
            self.app.notify("No context file directory")
            return
        if not self.context_name:
            self.app.notify("No context filename")
            return
        to_save = []
        for entry in self.context_entries:
            to_save.append({})
            write_to = to_save[-1]
            archive = entry.archive.input_path
            if archive:
                write_to["archive"] = str(archive)
            install_prefix = entry.install_prefix.value
            if install_prefix:
                write_to["installPrefix"] = install_prefix
            write_to["extractPaths"] = []
            for path in entry.extract_paths.input_paths:
                if path.path_selector.input_path and path.active:
                    write_to["extractPaths"].append(str(path.path_selector.input_path))
            container_prefix = entry.container_prefix.value
            if container_prefix:
                write_to["containerPrefix"] = container_prefix
        file_to_save = self.context_input.input_path / self.context_name.value
        try:
            with file_to_save.open("w") as f:
                f.write(json.dumps(to_save, indent=2))
        except IsADirectoryError:
            self.app.notify(f"Could not write to {file_to_save}")
            return
        self.app.notify(f"Wrote config to {file_to_save}")

    @textual.on(textual.widgets.Button.Pressed, "#load")
    def load(self):
        try:
            if not self.context_input.input_path:
                self.app.notify("No context file directory")
                return
            file_to_load = self.context_input.input_path / self.context_name.value
            with file_to_load.open() as config_file:
                js = json.load(config_file)
        except (FileNotFoundError, IsADirectoryError):
            self.app.notify(f"Could not find file {file_to_load}")
            return
        except json.JSONDecodeError:
            self.app.notify(f"Error when parsing JSON in {file_to_load}")
            return
        # Delete all other entries
        for ce in self.context_entries:
            ce.remove()
        self.context_entries = []
        self.context_count = 1
        for entry in js:
            self.context_entries.append(ContextEntry(self.context_count))
            self.context_count += 1
            cur_entry = self.context_entries[-1]
            if "archive" in entry:
                cur_entry.archive.input_path = pathlib.Path(entry["archive"])
            if "extractPaths" in entry:
                for ep in entry["extractPaths"]:
                    cur_entry.extract_paths.add_path(pathlib.Path(ep))
            if "installPrefix" in entry:
                cur_entry.install_prefix.value = entry["installPrefix"]
            if "containerPrefix" in entry:
                cur_entry.container_prefix.value = entry["containerPrefix"]
        for entry in self.context_entries:
            self.mount(entry, before="#add_context_entry")


class PluginSetting(textual.widgets.Static):
    __config_manager = surfactant.configmanager.ConfigManager()

    def __init__(self, plugin_name: str, info: surfactant.utils.get_plugin_settings.PluginSetting):
        super().__init__()
        self.plugin_name = plugin_name
        self.info = info

        match self.info.type_:
            case "str":
                self.input_field = textual.widgets.Input()
                default_value = self.info.default
                if default_value is None:
                    default_value = ""
                self.value = self.__config_manager.get(
                    self.plugin_name, self.info.name, default_value
                )
            case "bool":
                self.input_field = textual.widgets.Checkbox()
                # Have to convert from string to Boolean

                default_value = (
                    True if self.info.default is None else self.info.default.lower() == "true"
                )

                self.value = self.__config_manager.get(
                    self.plugin_name, self.info.name, default_value
                )

            case _:
                raise TypeError(f'Invalid plugin setting of type "{self.info.type_}"')

    def compose(self) -> textual.app.ComposeResult:
        # Set the value now - setting the Input value during __init__ was causing errors...
        self.input_field.value = self.value
        yield textual.containers.HorizontalGroup(
            textual.widgets.Label(self.info.name),
            textual.widgets.Button("?", id="help", tooltip=self.info.description),
        )
        yield self.input_field
        # To create extra spacing
        yield textual.widgets.Static("")

    @textual.on(textual.widgets.Button.Pressed, "#help")
    def show_help(self):
        self.app.push_screen(InfoScreen(self.info.description))


class PluginSettingsTab(textual.widgets.Static):
    __config_manager = surfactant.configmanager.ConfigManager()
    # Core settings - I don't think there's a good way to automatically extract these
    __setting = surfactant.utils.get_plugin_settings.PluginSetting
    __core_settings = [
        __setting(
            "output_format",
            "str",
            "SBOM output format, see 'surfactant generate --list_output_formats' for list of options",
            "CyTRICS",
        ),
        __setting("author_name", "str", "Name of the BOM author.", ""),
        __setting(
            "author_type",
            "str",
            "Type of the BOM author, such as name, organization, or program.",
            "",
        ),
        __setting(
            "include_all_files",
            "bool",
            "Include all files in the SBOM (default). Set to false to only include files with types recognized by Surfactant",
            "True",
        ),
    ]

    def __init__(self):
        super().__init__()
        plugins = {
            "core": self.__core_settings
        } | surfactant.utils.get_plugin_settings.extract_plugin_settings()
        self.plugin_settings = {}
        for name, settings in plugins.items():
            self.plugin_settings[name] = []
            for setting in settings:
                self.plugin_settings[name].append(PluginSetting(name, setting))

    def compose(self) -> textual.app.ComposeResult:
        for name, settings in self.plugin_settings.items():
            with textual.widgets.Collapsible(title=name, collapsed=True):
                yield from settings

        yield textual.widgets.Button("Save settings", id="save")

    @textual.on(textual.widgets.Button.Pressed, "#save")
    def save_settings(self):
        for name, settings in self.plugin_settings.items():
            for setting in settings:
                self.__config_manager.set(name, setting.info.name, setting.input_field.value)
        self.app.notify("Settings saved.")


class TUI(textual.app.App):
    """An app for running Surfactant commands"""

    BINDINGS = [
        ("d", "toggle_dark", "Toggle dark mode"),
        ("q", "quit", "Quit"),
    ]
    TITLE = "Surfactant TUI"
    CSS_PATH = "../ui-resources/tui.tcss"

    def __init__(self):
        super().__init__()
        self.generate_tab = GenerateTab()
        self.merge_tab = MergeTab()
        self.plugin_settings_tab = PluginSettingsTab()
        self.context_tab = ContextTab()

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Header()
        yield textual.widgets.Footer()
        with textual.widgets.TabbedContent():
            with textual.widgets.TabPane("Generate"):
                yield self.generate_tab
            with textual.widgets.TabPane("Merge"):
                yield self.merge_tab
            with textual.widgets.TabPane("Context"):
                yield self.context_tab
            with textual.widgets.TabPane("Settings"):
                yield self.plugin_settings_tab

    def action_toggle_dark(self) -> None:
        """A binding for toggling dark mode"""
        # pylint: disable-next=attribute-defined-outside-init
        self.theme = "textual-dark" if self.theme == "textual-light" else "textual-light"

    def action_quit(self) -> None:
        self.app.exit()


@click.command("tui")
def tui():
    """Run the Surfactant TUI for generating and merging SBOMs."""
    app = TUI()
    app.run()
