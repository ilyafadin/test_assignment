# test_assignment
**API provides methods:**

createUser(String name, String pass)

deleteUser(User user)

createRole(String roleName)

deleteRole(Role role)

addRoleToUser(User user, Role role)

createToken(String username)

authenticate(String username, String password)

invalidate(final String token)

checkRole(String token, Role role)

allRoles(String token)

