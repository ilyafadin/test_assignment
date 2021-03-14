package entities;

//import java.util.Base64;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;

public class User {

    private String name;
    private String pass;
    private HashSet<Role> roles = new HashSet<Role>();
    private String salt;

    public User(String name, String pass) {
        this.name = name;
        this.salt = name + "salt";

        String myHash = hashPassword(pass);

        this.pass = myHash;
    }

    public String hashPassword(String pass) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(pass.getBytes());
            md.update(this.salt.getBytes());
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("MD5 is not a valid message digest algorithm");
        }

        byte[] digest = md.digest();
        String myHash = DatatypeConverter
                .printHexBinary(digest).toUpperCase();
        return myHash;
    }

    public String getName(){
        return this.name;
    }

    public String getPass(){
        return this.pass;
    }

    public void addRole(Role role) {
        this.roles.add(role);
    }

    public HashSet<Role> getRoles() {
        return this.roles;
    }

}
