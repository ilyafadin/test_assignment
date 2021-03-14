package entities;

//import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
//import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
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
        String myHash = "";
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = factory.generateSecret(spec).getEncoded();
        } catch (java.security.spec.InvalidKeySpecException e) {
            System.err.println("InvalidKeySpecException");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("NoSuchProviderException");
        }
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
