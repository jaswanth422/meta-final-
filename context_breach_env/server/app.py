from openenv.core.env_server import create_app

from context_breach_env.models import ContextBreachAction, ContextBreachObservation
from context_breach_env.server.context_breach_environment import ContextBreachEnvironment


app = create_app(
    ContextBreachEnvironment,
    ContextBreachAction,
    ContextBreachObservation,
    env_name="context_breach_env",
    max_concurrent_envs=64,
)
