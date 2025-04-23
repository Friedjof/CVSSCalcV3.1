import datetime
import re
from nicegui import ui
from nicegui.element import Element

class DropdownWithHelp(Element):
    def __init__(self, label: str, key: str, options: dict, help_text: str, on_change: callable):
        self.key = key
        self.options = options
        self.title = label
        super().__init__('div')
        with self.classes('flex dropdown').style('align-items: flex-end'):
            # Dropdown
            self.dropdown = ui.select(
                options=list(options.keys()),
                label=label,
                on_change=on_change,
            ).style('width: 85%')

            self.dropdown.value = list(options.keys())[0]

            self.help_button = ui.button(
                '?', on_click=lambda: self.show_help_dialog(help_text, options)
            ).props('flat dense round').classes('text-white bg-primary border border-primary shadow-lg').style(
                'margin: auto; display: flex; justify-content: center; align-items: center;')

    def get_key(self) -> str:
        return self.key

    def get_value(self) -> tuple:
        try:
            return self.options[self.dropdown.value][:-1]
        except KeyError:
            return 0.0, 'X'

    def get_title(self) -> str:
        return self.title

    def set_tag(self, tag: str):
        for key, value in self.options.items():
            if value[1] == tag:
                self.dropdown.value = key
                break

    def reset(self):
        if self.dropdown.value != list(self.options.keys())[0]:
            self.dropdown.value = list(self.options.keys())[0]

    def show_help_dialog(self, help_text: str, options: dict):
        with ui.dialog() as dialog:
            with ui.card():
                ui.label(f'Explanation: {self.dropdown.label}').classes('text-lg font-bold')
                ui.separator()
                ui.label(help_text)
                with ui.list().classes('text-sm'):
                    for key, value in options.items():
                        ui.label(f"• {key}: {value[2]}").style('margin-bottom: 4px;')
                ui.button('OK', on_click=dialog.close)
        dialog.open()


class VectorInput(Element):
    def __init__(self, label: str):
        super().__init__('div')
        self.dropdown_objects = []
        self.score = .0
        self.vector = ""
        with self.classes('nice-card'):
            # Eingabefeld
            self.input = ui.input(label=label, on_change=self.parse_vector).style('width: 100%;')

            # Score-Anzeige
            self.score_label = ui.label("-").classes('score')

    @staticmethod
    def get_criticality(score: float) -> str:
        if score < 0:
            return 'none'
        elif score < 4:
            return 'low'
        elif score < 7:
            return 'medium'
        elif score < 9:
            return 'high'
        else:
            return 'critical'

    def set_score(self, score: float):
        if self.score_label.text == f"Score: {score:.1f}":
            return

        self.score = score
        self.score_label.classes(remove='none low medium high critical')

        criticality = self.get_criticality(score)

        self.score_label.classes(criticality)
        self.score_label.text = f"Score: {score:.1f}"

    def get_score(self) -> float:
        return self.score

    def set_vector(self, vector: str):
        self.vector = vector
        self.input.value = vector

    def set_dropdown_objects(self, dropdown_objects: list[DropdownWithHelp]):
        self.dropdown_objects = dropdown_objects
        self.calculate_vector()

    def parse_vector(self) -> None:
        vector = self.input.value

        if re.search(r"^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NHL]/I:[NHL]/A:[NHL])$", vector) is None:
            self.set_score(.0)
            return

        # Parse the vector
        vector = vector.strip()

        parts = vector.replace("CVSS:3.1/", "").split("/")
        values = {part.split(":")[0]: part.split(":")[1] for part in parts}

        # Update the dropdowns
        for dropdown in self.dropdown_objects:
            if dropdown.get_key() in values:
                if dropdown.get_value()[1] != values[dropdown.get_key()]:
                    dropdown.set_tag(values[dropdown.get_key()])

        # Calculate the vector and score
        self.calculate_vector()

    def calculate_vector(self) -> None:
        data = dict()
        for dropdown in self.dropdown_objects:
            data.update({dropdown.get_key(): dropdown.get_value()})

        if len(data) != 8:
            return

        # Calculate the vector
        vector = f"CVSS:3.1/AV:{data['AV'][1]}/AC:{data['AC'][1]}/PR:{data['PR'][1]}/UI:{data['UI'][1]}/S:{data['S'][1]}/C:{data['C'][1]}/I:{data['I'][1]}/A:{data['A'][1]}"

        # Calculate the score
        impact = 1 - ((1 - data['C'][0]) * (1 - data['I'][0]) * (1 - data['A'][0]))
        impact_score = 6.42 * impact if data['S'][1] == 'U' else 7.52 * impact
        exploitability = 8.22 * data['AV'][0] * data['AC'][0] * data['PR'][0] * data['UI'][0]

        if impact <= .0:
            base_score = .0
        elif data['S'][1] == 'U':
            base_score = min(impact_score + exploitability, 10)
        else:
            base_score = min(1.08 * (impact_score + exploitability), 10)

        self.set_vector(vector)
        self.set_score(base_score)
