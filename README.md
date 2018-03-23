[![Join the chat at https://gitter.im/auto_re/Lobby](https://badges.gitter.im/auto_re/Lobby.svg)](https://gitter.im/auto_re/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Features
========

## 1. Auto-renaming dummy-named functions, which have one API call or jump to the imported API

### Before
![auto_rename_src.png](docs/auto_rename_src.png)

### After
![auto_rename_dst.png](docs/auto_rename_dst.png)


## 2. Assigning TAGS to functions accordingly to called API-indicators inside

* Sets tags as repeatable function comments and displays TAG tree in the separate view


Some screenshots of TAGS view:

![tags_view_0.png](docs/tags_view_0.png)

![tags_view_1.png](docs/tags_view_1.png)

How TAGs look in unexplored code:
![tags_in_unexplored_code.png](docs/tags_in_unexplored_code.png)


You can easily rename function using its context menu or just pressing `n` hotkey:

![function_rename.png](docs/function_rename.png)

# Installation

Just copy `auto_re.py` to the `IDA\plugins` directory and it will be available through `Edit -> Plugins -> Auto RE` menu