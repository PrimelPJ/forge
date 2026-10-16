import pytest

from forge.simulator.process import PlantState


@pytest.fixture
def plant() -> PlantState:
    return PlantState()
