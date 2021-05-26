package burp.model;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HttpRequestResponse implements IHttpRequestResponse {

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    /**
     * Creates <code>HttpRequestResponse</code> instance.
     *
     * @param request     The bytes array of the request data
     * @param response    The bytes array of the request data
     * @param comment     The user-annotated comment for this item, if applicable.
     * @param highlight   The user-annotated highlight for this item, if applicable.
     * @param httpService The HTTP service for this request / response.
     */

    public HttpRequestResponse(byte[] request, byte[] response, String comment, String highlight, IHttpService httpService) {
        this.request = request;
        this.response = response;
        this.comment = comment;
        this.highlight = highlight;
        this.httpService = httpService;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        this.request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        this.response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }

}

