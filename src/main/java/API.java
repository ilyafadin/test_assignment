import java.lang.reflect.Array;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.*;

//import com.sun.org.apache.bcel.internal.generic.RETURN;
import entities.Response;
import entities.Role;
import entities.User;
import entities.AuthDetails;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.function.Predicate;

import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class API {

    private static Set<User> users = new HashSet<>();
    private static Set<Role> roles = new HashSet<>();


    private static List<AuthDetails> authDetails = new ArrayList<AuthDetails>();

    public static void main(String[] args) {
        System.out.println("Test assignment");
    }

    public Response createUser(String name, String pass) {

        boolean contains = users.stream().anyMatch(u -> u.getName().equals(name));

        if (contains) {
            return new Response(422, String.format("user %s already exists", name));
        } else {
            if (!name.equals("")) {
                User newUser = new User(name, pass);
                users.add(newUser);
                return new Response(200, String.format("user %s created", name));
            } else return new Response(422, "user name is empty");
        }
    }


    public Response deleteUser(User user) {

        if (!users.contains(user)) {
            return new Response(422, String.format("user %s does not exists", user.getName()));
        } else {
            users.remove(user);
            return new Response(200, String.format("user %s has been removed", user.getName()));
        }
    }


    public Response createRole(String roleName) {
        boolean roleFound = roles.stream().anyMatch(r -> r.getName().equals(roleName));

        if (roleFound) {
            return new Response(422, String.format("role %s already exists", roleName));
        } else {
            Role newRole = new Role(roleName);
            roles.add(newRole);
            return new Response(200, String.format("role %s created", roleName));
        }
    }

    public Response deleteRole(Role role) {

        if (!roles.contains(role)) {
            return new Response(422, String.format("role %s does not exists", role.getName()));
        } else {
            roles.remove(role);
            return new Response(200, String.format("role %s has been deleted", role.getName()));
        }
    }

    public Response addRoleToUser(User user, Role role) {

        for (User u : users) {
            if (u.getName().equals(user.getName())) {
                Set<Role> userRoles = u.getRoles();
                boolean roleFound = userRoles.contains(role);
                if (roleFound) {
                    return new Response(422, String.format("role %s for user %s already exists",
                            role.getName(), user.getName()));
                } else {
                    u.addRole(role);
                }
            }
        }

        return new Response(200, String.format("role %s has been added", role.getName()));
    }

    private String createToken(String username) {
        String myHash = "";
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(username.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = factory.generateSecret(spec).getEncoded();
        } catch (java.security.spec.InvalidKeySpecException e) {
            System.err.println("InvalidKeySpecException");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("NoSuchProviderException");
        }
        return myHash;

    }

    public Response authenticate(String username, String password) {

        User userFound = null;
        for (User u : users) {
            if (u.getName().equals(username)) {
                userFound = u;
            }
        }

        if (userFound != null) {
            String thisUserPass = userFound.hashPassword(password);
            if (thisUserPass.equals(userFound.getPass())) {
                Long curtime = System.currentTimeMillis();
                String newToken = createToken(username);
                AuthDetails newTokenTuple = new AuthDetails(username, newToken, curtime);
                authDetails.add(newTokenTuple);
                return new Response(200, newToken);
            } else
                return new Response(422, String.format("password for %s is not correct", username));

        } else
            return new Response(422, String.format("username %s not found", username));
    }

    public void invalidate(final String token) {
        AuthDetails currentAuthDetails = null;
        for (AuthDetails a : authDetails) {
            if (a.getToken().equals(token)) {
                currentAuthDetails = a;
            }
        }

        if (currentAuthDetails != null) {
            authDetails.remove(currentAuthDetails);
        }
    }

    public Boolean checkRole(String token, Role role) {

        Long currentTime = System.currentTimeMillis();

        AuthDetails authDetail = null;

        for (AuthDetails a : authDetails) {
            if (a.getToken().equals(token))
                authDetail = a;
        }

        if (authDetail != null) {
            String username = authDetail.getUsername();
            Long tokenTime = authDetail.getTokenExpiration();

            Long tokenLifeHours = TimeUnit.MILLISECONDS.toHours(currentTime - tokenTime);
            //can change to tokenLifeSeconds in if below for testing purpose
            //Long tokenLifeSeconds = TimeUnit.MILLISECONDS.toSeconds(currentTime - tokenTime); //

            if (tokenLifeHours < 2 ) {
                Optional<Boolean> rolesFound = users.stream().filter(u -> u.getName().equals(username)).map(u -> {
                    HashSet<Role> userRoles = u.getRoles();
                    return userRoles.contains(role);
                }).findFirst();
                return rolesFound.orElse(false);
            } else {
                return false;
            }
        } else return false;

    }

    public Optional<HashSet<Role>> allRoles(String token) {
        AuthDetails authDetail = null;

        for (AuthDetails a : authDetails) {
            if (a.getToken().equals(token))
                authDetail = a;
        }

        String username = "";
        if (authDetail != null) {
            username = authDetail.getUsername();
        } else {
            return Optional.empty();
        }

        ArrayList<String> usernames = new ArrayList<>();
        for (User u : users) {
            usernames.add(u.getName());
        }


        HashSet<Role> userRoles = new HashSet<>();
        if (usernames.contains(username)) {
            for (User u : users) {
                userRoles = u.getRoles();
            }
            return Optional.of(userRoles);
        } else return Optional.empty();

    }



    private void showUsersAndTreirRoles(String fname) {
        System.out.println(fname);
        for (User u : users) {
            System.out.println(u.getName());
            for(Role r : u.getRoles()) {
                System.out.println(r.getName());
            }
        }
    }

    private void showRoles(String fname) {
        System.out.println(fname);
        for (Role r : roles) {
            System.out.println(r.getName());
        }
    }


}
