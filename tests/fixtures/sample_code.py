"""
Fixture containing both vulnerable and secure code patterns for testing the AST scanner.
"""

# VULNERABLE PATTERN 1: Direct f-string in cursor.execute
def vuln_direct_fstring(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

# VULNERABLE PATTERN 2: Intermediate f-string assigned to variable
def vuln_variable_fstring(cursor, order_id):
    query = f"SELECT * FROM orders WHERE order_id = '{order_id}'"
    cursor.execute(query)

# VULNERABLE PATTERN 3: String concatenation (+)
def vuln_concat(cursor, role):
    sql = "SELECT id, name FROM accounts WHERE role = '" + role + "'"
    cursor.execute(sql)

# VULNERABLE PATTERN 4: String .format()
def vuln_format(cursor, category):
    statement = "SELECT * FROM products WHERE cat = '{}'".format(category)
    cursor.execute(statement)

# SAFE PATTERN 1: Parameterized query placeholder with tuple
def safe_parameterized(cursor, user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

# SAFE PATTERN 2: Static constant query
def safe_constant(cursor):
    cursor.execute("SELECT id, name FROM static_roles")
