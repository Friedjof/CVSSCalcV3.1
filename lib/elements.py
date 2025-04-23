import re
from datetime import datetime

from nicegui import ui
from nicegui.element import Element


class DropdownWithHelp(Element):
    def __init__(self, label: str, key: str, options: dict, help_text: str, on_change: callable, value: str = None):
        self.key = key
        self.options = options
        self.title = label
        super().__init__('div')
        with self.classes('flex dropdown').style('align-items: flex-end'):
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

        if value:
            self.set_tag(value)

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
    def __init__(self, label: str, header: "Header", vector: str = None):
        super().__init__('div')
        self.dropdown_objects = []
        self.score = .0
        self.header = header
        self.vector = ""

        with self.classes('nice-card vector-input'):
            # Eingabefeld
            self.input = ui.input(label=label, on_change=self.parse_vector).style('width: 100%;')

            # Score-Anzeige
            self.score_label = ui.label("-").classes('score')

        if vector:
            self.set_vector(vector)

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
        self.header.set_link(f'/?vector={vector}')

    def get_vector(self) -> str:
        return self.input.value

    def set_dropdown_objects(self, dropdown_objects: list[DropdownWithHelp]):
        self.dropdown_objects = dropdown_objects
        self.calculate_vector()

    def parse_vector(self) -> None:
        values = self.get_dropdown_values()

        if values is None:
            self.set_score(.0)
            return

        # Update the dropdowns
        for dropdown in self.dropdown_objects:
            if dropdown.get_key() in values:
                if dropdown.get_value()[1] != values[dropdown.get_key()]:
                    dropdown.set_tag(values[dropdown.get_key()])

        # Calculate the vector and score
        self.calculate_vector()

    def get_data(self) -> dict:
        data = dict()
        for dropdown in self.dropdown_objects:
            data.update({dropdown.get_key(): dropdown.get_value()})
        return data

    @staticmethod
    def calculate(av: float, ac: float, pr: float, ui_: float, s: str, c: float, i: float, a: float) -> tuple:
        # Calculate the score
        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact_score = 6.42 * impact if s == 'C' else 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        exploitability = 8.22 * av * ac * pr * ui_

        if s == 'U':
            base_score = min(impact_score + exploitability, 10)
        else:
            base_score = min(1.08 * (impact_score + exploitability), 10)

        return impact, impact_score, exploitability, base_score

    def get_dropdown_values(self) -> dict | None:
        """
        Get the dropdown value from the vector string.
        :return: A tuple of values for AV, AC, PR, UI, S, C, I, A.
        """
        if re.search(r"^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NHL]/I:[NHL]/A:[NHL])$", self.input.value) is None:
            return None

        # Parse the vector
        vector = self.input.value.strip()
        parts = vector.replace("CVSS:3.1/", "").split("/")
        return {part.split(":")[0]: part.split(":")[1] for part in parts}

    def calculate_vector(self) -> None:
        data = self.get_data()

        if len(data) != 8:
            return

        # Calculate the vector
        vector = f"CVSS:3.1/AV:{data['AV'][1]}/AC:{data['AC'][1]}/PR:{data['PR'][1]}/UI:{data['UI'][1]}/S:{data['S'][1]}/C:{data['C'][1]}/I:{data['I'][1]}/A:{data['A'][1]}"

        # Calculate the score
        impact, impact_score, exploitability, base_score = self.calculate(
            data['AV'][0], data['AC'][0], data['PR'][0], data['UI'][0],
            data['S'][1], data['C'][0], data['I'][0], data['A'][0]
        )

        self.set_vector(vector)
        self.set_score(base_score)


class Header(Element):
    def __init__(self):
        super().__init__('div')
        self.link = None
        with self.classes('navbar'):
            ui.label('CVSS v3.1 Calculator 🧮').classes('title')
            ui.button('', on_click=self.share).props('icon=share').classes(
                    'share-button'
                ).style('margin-left: auto;')

    def set_link(self, link: str) -> None:
        self.link = link

    def share(self) -> None:
        ui.notify('Link copied to clipboard!', color='success')
        ui.run_javascript(f'''
            const fullLink = window.location.origin + "{self.link}";
            navigator.clipboard.writeText(fullLink);
        ''')

class Footer:
    def __init__(self, vector_input: VectorInput):
        self.vector_input = vector_input
        self.label = None
        self.dialog = None
        self.latex_output = None
        self.create_footer()

    def create_footer(self):
        with ui.footer().classes('footer'):
            with ui.row().classes('footer-content'):
                ui.link('Legal Notice', 'https://gist.github.com/Friedjof/9aa6bee1b19f73d48fe72f0af5fffc5d').classes('footer-link')
                ui.link('Friedjof Noweck', 'https://github.com/Friedjof').classes('footer-link')
                ui.link(
                    'GitHub',
                    f'https://github.com/Friedjof/CVSSCalcV3.1/releases/tag/{self.get_version()}',
                ).classes('footer-link')

            ui.button('📄', on_click=self.show_dialog).classes('round-button')

    def show_dialog(self):
        if not self.dialog:
            with ui.dialog() as self.dialog:
                with ui.card():
                    ui.label('More Information').classes('text-lg font-bold')
                    ui.separator()
                    self.latex_output = ui.html('<div id="latex-cvss"></div>').classes('dialog-content')
                    ui.button('Close', on_click=self.dialog.close).classes('dialog-close-button')

        self.dialog.open()

        data = self.vector_input.get_data()
        av, ac, pr, ui_, s, c, i, a = data['AV'][0], data['AC'][0], data['PR'][0], data['UI'][0], data['S'][1], data['C'][0], data['I'][0], data['A'][0]

        impact, impact_score, exploitability, base_score = self.vector_input.calculate(
            av, ac, pr, ui_, s, c, i, a
        )

        if s == 'U':
            base_score_str = fr"{{Base Score}} = min\left( {impact_score:.2f} + {exploitability:.2f}, 10 \right) = \underline{{\underline{{{base_score:.2f}}}}} \text"
            impact_score_str = fr"{{Impact Score}} = 7.52 \cdot \left( {impact:.2f} - 0.029 \right) - 3.25 \cdot \left( {impact:.2f} - 0.02 \right)^{15} = {impact_score:.2f}"
        else:
            base_score_str = fr"{{Base Score}} = min\left( 1.08 \cdot {impact_score:.2f} + {exploitability:.2f}, 10 \right) = \underline{{\underline{{{base_score:.2f}}}}} \text"
            impact_score_str = fr"{{Impact Score}} = 6.42 \cdot {impact:.2f} = {impact_score:.2f}"

        latex_expression = fr"""
        \text{{Impact}} = 1 - (1 - {c}) \cdot (1 - {i}) \cdot (1 - {a}) = {impact:.2f} \\
        \text{impact_score_str} \\
        \text{{Exploitability}} = 8.22 \cdot {av} \cdot {ac} \cdot {pr} \cdot {ui_} = {exploitability:.2f} \\
        \text{base_score_str} \\
        """

        ui.run_javascript(f'''
            katex.render(String.raw`{latex_expression}`, document.getElementById("latex-cvss"), {{
                displayMode: true
            }});
        ''')

    @staticmethod
    def get_version() -> str:
        try:
            with open('VERSION', 'r') as version_file:
                return version_file.read().strip()
        except FileNotFoundError:
            return "unknown"
