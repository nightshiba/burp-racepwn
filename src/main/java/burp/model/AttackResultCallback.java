package burp.model;

public interface AttackResultCallback {
    void setServerResponse(int serverID, byte[] response);
}
