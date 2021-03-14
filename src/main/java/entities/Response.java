package entities;

public class Response {

    private Integer code;
    private String message;

    public Response(Integer code, String message) {
        this.code = code;
        this.message = message;
    }

    public Integer getCode() {
        return this.code;
    }

    public String getMassage() {
        return this.message;
    }
}
