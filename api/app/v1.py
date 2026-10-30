"""Router de ``/v1``: toda ruta de aquí exige autenticación (diseño §3).

La dependencia va en el router para que una ruta nueva no pueda olvidarla. Ojo: FastAPI lee
el cuerpo **antes** de resolver las dependencias si la ruta declara un parámetro de cuerpo
(``Body``, ``Form``, ``File`` o un modelo). Por eso ninguna ruta de ``/v1`` los declara: lee
de ``request.stream()`` dentro de la función. ``test_autenticacion.py`` lo comprueba.

Todavía no se incluye en ``crear_app``: no tiene rutas, y no se dejan endpoints de relleno.
Se incluye con el primer endpoint real.
"""

from fastapi import APIRouter, Depends

from api.app.autenticacion import autenticar


def crear_router_v1() -> APIRouter:
    return APIRouter(prefix="/v1", dependencies=[Depends(autenticar)])
