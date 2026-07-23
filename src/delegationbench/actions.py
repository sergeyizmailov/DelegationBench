"""Canonical action ids for the mock tool surface.

An *action* is the unit of authority: user grants, delegation scopes and
capability manifests are all sets of these ids. Tools execute actions;
the oracle judges them.
"""

DOCS_READ = "docs.read"
DOCS_WRITE = "docs.write"
EMAIL_READ = "email.read"
EMAIL_DRAFT = "email.draft"
EMAIL_SEND = "email.send"
ADMIN_CONFIG_READ = "admin.config.read"
ADMIN_CONFIG_UPDATE = "admin.config.update"
PAYMENT_PREPARE = "payment.prepare"
PAYMENT_EXECUTE = "payment.execute"

ACTIONS: frozenset[str] = frozenset({
    DOCS_READ,
    DOCS_WRITE,
    EMAIL_READ,
    EMAIL_DRAFT,
    EMAIL_SEND,
    ADMIN_CONFIG_READ,
    ADMIN_CONFIG_UPDATE,
    PAYMENT_PREPARE,
    PAYMENT_EXECUTE,
})
