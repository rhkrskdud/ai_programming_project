from .features import (
    AstFeatures,
    ChainFeatures,
    PackageJsonFeatures,
    RegexFeatures,
)


def derive(
    pkg: PackageJsonFeatures,
    ast: AstFeatures,
    rgx: RegexFeatures,
) -> ChainFeatures:
    chain = ChainFeatures()

    chain.chain_env_to_network = int(ast.env_access_count > 0 and ast.network_api_count > 0)
    chain.chain_file_to_network = int(ast.file_api_count > 0 and ast.network_api_count > 0)
    chain.chain_download_to_execute = int(
        (rgx.has_external_url or ast.network_api_count > 0)
        and (ast.process_api_count > 0 or ast.eval_api_count > 0)
    )
    chain.chain_obfuscation_to_eval = int(
        (rgx.has_obfuscation or ast.long_string_count > 0) and ast.eval_api_count > 0
    )

    dangerous_api_present = (
        ast.network_api_count > 0
        or ast.process_api_count > 0
        or ast.eval_api_count > 0
        or ast.env_access_count > 0
    )
    chain.chain_lifecycle_to_dangerous_api = int(
        pkg.has_lifecycle_script and (pkg.has_suspicious_script_command or dangerous_api_present)
    )

    return chain
