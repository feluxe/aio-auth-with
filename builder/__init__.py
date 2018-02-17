from typing import Union
from cmdi import CmdResult, print_summary as print_summary_
from buildlib import yaml, semver, build, git

CFG_FILE = 'Project'
CFG = yaml.loadfile(
    file=CFG_FILE,
    keep_order=True
)

__version__ = CFG.get('version')


def build_wheel(
) -> Union[CmdResult, None]:
    """"""
    return build.cmd.build_python_wheel(
        clean_dir=True,
    )


def push_registry(
) -> Union[CmdResult, None]:
    """"""
    return build.cmd.push_python_wheel_to_pypi(
        clean_dir=True,
    )


def bump_version() -> Union[CmdResult, None]:
    """
    Bump (update) version number in CONFIG.yaml.
    """
    new_version: str = semver.prompt.semver_num_by_choice(
        cur_version=CFG.get('version')
    )

    return build.cmd.update_version_num_in_cfg(
        config_file=CFG_FILE,
        semver_num=new_version,
    )


def bump_git(
    ask_bump_any_git=False,
    print_summary=True,
    version=None,
):
    """"""
    cur_version = CFG.get('version')
    new_version = version or cur_version

    if not version and build.prompt.should_update_version(
        default='y',
    ):
        new_version = bump_version().val

    seq_settings = git.seq.get_settings_from_user(
        version=new_version,
        ask_bump_any_git=ask_bump_any_git,
        should_tag_default_val=cur_version != new_version,
    )

    results = git.seq.bump_sequence(seq_settings)

    if print_summary:
        print_summary_(results)

    return results


def bump_all() -> None:
    """"""
    results = []
    cur_version = CFG.get('version')
    new_version = cur_version

    if build.prompt.should_update_version(
        default='y'
    ):
        new_version = bump_version().val

    results += bump_git(
        version=new_version,
        ask_bump_any_git=True,
        print_summary=False,
    )

    should_build_wheel: bool = build.prompt.should_build_wheel(
        default='y',
    )

    should_push_registry: bool = build.prompt.should_push_pypi(
        default='y' if cur_version != new_version else 'n',
    )

    if should_build_wheel:
        results.append(build.cmd.build_python_wheel(
            clean_dir=True,
        ))

    if should_push_registry:
        results.append(build.cmd.push_python_wheel_to_pypi(
            clean_dir=True,
        ))

    print_summary_(results)