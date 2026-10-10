"""Attack PoC catalogue.

Each submodule contributes Attack subclasses. The registry below is consumed
by the corpus builder to enumerate cases. Add new attacks by importing the
class here and appending to ATTACK_CLASSES.
"""
from cym500.redteam.attacks.tool_poisoning.hidden_instruction import HiddenInstructionAttack
from cym500.redteam.attacks.rug_pull.post_approval_swap import PostApprovalSwapAttack
from cym500.redteam.attacks.cross_server_exfil.indirect_chain import IndirectChainAttack
from cym500.redteam.attacks.sampling_injection.malicious_sampling_response import MaliciousSamplingAttack
from cym500.redteam.attacks.schema_poisoning.x_instruction_field import XInstructionFieldAttack
from cym500.redteam.attacks.supply_chain.dependency_typosquat import TyposquatAttack
from cym500.redteam.attacks.prompt_injection_via_output.search_result_injection import SearchResultInjectionAttack
from cym500.redteam.attacks.credential_leakage.env_exfil_via_tool_call import EnvExfilAttack

ATTACK_CLASSES = [
    HiddenInstructionAttack,
    PostApprovalSwapAttack,
    IndirectChainAttack,
    MaliciousSamplingAttack,
    XInstructionFieldAttack,
    TyposquatAttack,
    SearchResultInjectionAttack,
    EnvExfilAttack,
]
