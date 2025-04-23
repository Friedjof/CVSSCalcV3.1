import re
from datetime import datetime

from nicegui import ui

from lib.functions import get_version, parse_vector
from lib.elements import DropdownWithHelp, VectorInput
from lib.metrics import metrics


@ui.page('/')
def main():
    dropdown_objects = []
    ui.page_title("CVSS v3.1 Calculator")
    ui.add_css('static/styles.css')

    with ui.column().classes('container'):
        ui.label('💻 CVSS v3.1 Calculator – Base Score').classes('title')

        vector_input = VectorInput(
            label='CVSS Vector (Optional)'
        )

        with ui.row().classes('nice-card'):
            for i, (metric_key, metric) in enumerate(metrics.items()):
                # Create a dropdown for each metric
                dropdown_objects.append(DropdownWithHelp(
                    label=metric['title'],
                    key=metric_key,
                    options=metric['options'],
                    help_text=metric['help_text'],
                    on_change=vector_input.calculate_vector
                ))
                dropdown_objects[i].classes('dropdown')

        vector_input.set_dropdown_objects(dropdown_objects)
    # Add footer
    with ui.footer().classes('nice-card').style('text-align: center; display: flex; align-items: center;'):
        ui.label(f"© {datetime.now().year}").style(
            'margin-right: 4px;'
        )
        ui.link(
            'Friedjof Noweck',
            'https://github.com/Friedjof',
        ).style(
            'color: #ffff00; text-decoration: none;'
        )
        ui.link(
            'Version on GitHub',
            f'https://github.com/Friedjof/CVSSCalcV3.1/releases/tag/{get_version()}',
        ).style(
            'color: #ffff00; text-decoration: none;'
        )
        ui.link(
            'Legal Notice',
            'https://gist.github.com/Friedjof/9aa6bee1b19f73d48fe72f0af5fffc5d'
        ).style(
            'color: #ffff00; text-decoration: none; margin-left: 4px;'
        )

ui.run(favicon="🧮")
