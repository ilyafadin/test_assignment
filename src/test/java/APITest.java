import entities.Response;
import entities.Role;
import entities.User;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class APITest {

    public void printResponse(Response response){
        System.out.println(response.getCode() + " " + response.getMassage());
    }

    @Test
    public void createUserTest() {
        API api = new API();
        Response result = api.createUser("anton", "pass");
        printResponse(result);
        assert(result.getCode().equals(200));
    }

    @Test
    public void createUserDuplicateUSerNameTest() {
        API api = new API();
        Response result = api.createUser("anton", "pass");
        Response result2 = api.createUser("anton", "pass");
        printResponse(result);
        printResponse(result2);
        assert(result2.getCode().equals(422));
    }

    @Test
    public void createEmptyUserTest() {
        API api = new API();
        Response result = api.createUser("", "pass");
        printResponse(result);
        assert(result.getCode().equals(422));
    }

    @Test
    public void deleteUserTest() {
        API api = new API();
        api.createUser("anton", "pass");
        Response result = api.deleteUser(new User("anton", "pass"));
        printResponse(result);
        assert(result.getCode().equals(200));
    }

    @Test
    public void deleteNonExistentUserTest() {
        API api = new API();
        api.createUser("anton", "pass");
        Response result = api.deleteUser(new User("john", "pass"));
        printResponse(result);
        assert(result.getCode().equals(422));
    }

    @Test
    public void createRoleTest() {
        API api = new API();
        Response result = api.createRole("admin");
        assert(result.getCode().equals(200));
    }

    @Test
    public void deleteRoleTest() {
        API api = new API();
        api.createRole("admin");
        Response result = api.deleteRole(new Role("admin"));
        printResponse(result);
        assert(result.getCode().equals(200));
    }

    @Test
    public void addRoleToUserTest() {
        API api = new API();
        api.createUser("anton", "pass");
        api.createRole("admin");
        Response result = api.addRoleToUser(new User("anton", "pass"), new Role("admin"));
        printResponse(result);
        assert(result.getCode().equals(200));
    }

    @Test
    public void authenticateTest() {
        API api = new API();
        api.createUser("anton", "pass");
        Response result = api.authenticate("anton", "pass");
        printResponse(result);
        assert(result.getCode().equals(200));

    }

    @Test
    public void authenticateAnonymousTest() {
        API api = new API();
        api.createUser("anton", "pass");
        Response result = api.authenticate("", "");
        printResponse(result);
        assert(result.getCode().equals(422));

    }

    @Test
    public void invalidateTest() {
        API api = new API();
        api.createUser("anton", "pass");
        Response result = api.authenticate("anton", "pass");
        printResponse(result);
        api.invalidate(result.getMassage());
        assert(true);
    }

    @Test
    public void checkRoleTest() {
        API api = new API();
        api.createUser("anton", "pass");
        api.createRole("admin");
        api.addRoleToUser(new User("anton", "pass"), new Role("admin"));
        Response result = api.authenticate("anton", "pass");

        //can test if fails with seconds
        //try {
        //    TimeUnit.SECONDS.sleep(3);
        //}
        //catch (InterruptedException e) {
        //    System.err.println("TimeUnit.SECONDS.sleep fail");
        //}

        Boolean result2 = api.checkRole(result.getMassage(), new Role("admin"));

        assert (result2.equals(true));

    }

    @Test
    public void allRolesTest() {
        API api = new API();
        api.createUser("anton", "pass");
        api.createRole("admin");
        api.addRoleToUser(new User("anton", "pass"), new Role("admin"));
        Response result = api.authenticate("anton", "pass");

        Optional<HashSet<Role>> roles = api.allRoles(result.getMassage());

        ArrayList<String> userRoles = new ArrayList<>();
        for (Role r : roles.get()) {
            userRoles.add(r.getName());
        }

        assert (userRoles.contains("admin"));

    }


}
