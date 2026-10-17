# Deep imports fixture

This file imports one level down: @chain/one.md
It also imports a shared file: @shared/common.md

A fenced block that names a file does not import it:

```
@chain/fenced-target.md
```

An inline code span does not import either: `@chain/inline-target.md`

A home path is external and is never read: @~/.ssh/config
