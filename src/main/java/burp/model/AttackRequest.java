package burp.model;

import org.json.JSONArray;
import org.json.JSONObject;

public class AttackRequest {
    private final JSONArray jsonConfig;

    /**
     * This constructor is used to create object using existing JSON configuration string.
     *
     * @param jsonConfig The racepwn config string in JSON format.
     */
    private AttackRequest(String jsonConfig) {
        this.jsonConfig = new JSONArray(jsonConfig);
    }

    /**
     * This constructor is used to create object using existing JSON object.
     *
     * @param jsonConfig The racepwn config JSONArray.
     */
    private AttackRequest(JSONArray jsonConfig) {
        this.jsonConfig = jsonConfig;
    }

    /**
     * This method is used to retrieve a JSON configuration string.
     *
     * @return The racepwn config string in JSON format.
     */
    public String getJsonConfig() {
        return jsonConfig.toString();
    }

    public static class RequestBuilder {
        // Race section
        private String type = "parallel";
        private int delayTimeUsec = 10000;
        private int lastChunkSize = 10;

        // Raw section
        private String host = "example.com";
        private int port = 443;
        private String protocol = "https";
        // Race params
        private String data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        private int count = 10;


        /**
         * This method is used to build JSON configuration object using default or updated parameters.
         *
         * @return <code>RequestConfig</code> instance based on current configuration state.
         */
        public AttackRequest build() {
            JSONArray config = new JSONArray();
            JSONObject body = new JSONObject();
            body.put("race", getRaceSettings());
            body.put("raw", getRawSettings());
            config.put(body);
            return new AttackRequest(config);
        }

        /**
         * This method is used to create object using existing JSON configuration.
         *
         * @param jsonConfig The config string in JSON format.
         * @return <code>RequestConfig</code> instance based on given configuration.
         */
        public AttackRequest with(String jsonConfig) {
            return new AttackRequest(jsonConfig);
        }

        private JSONObject getRawSettings() {
            JSONObject raw = new JSONObject();
            raw.put("host", this.protocol + "://" + this.host + ":" + this.port);
            raw.put("ssl", isHttps(this.protocol));

            JSONObject raceParam = new JSONObject();
            raceParam.put("data", this.data);
            raceParam.put("count", this.count);

            raw.put("race_param", new JSONArray().put(raceParam));
            return raw;
        }

        private JSONObject getRaceSettings() {
            JSONObject race = new JSONObject();
            race.put("type", this.type);
            race.put("delay_time_usec", this.delayTimeUsec);
            race.put("last_chunk_size", this.lastChunkSize);
            return race;
        }

        /**
         * Sets the target server's URL host.
         *
         * @param host A string representing the target server's host.
         */
        public void setHost(String host) {
            this.host = host;
        }

        /**
         * Sets the target server's URL port.
         *
         * @param port An integer representing the target server's port.
         */
        public void setPort(int port) {
            this.port = port;
        }

        /**
         * Sets the target server's URL protocol.
         *
         * @param protocol A string representing the target server's protocol.
         */
        public void setProtocol(String protocol) {
            this.protocol = protocol;
        }

        private static boolean isHttps(String protocol) {
            return protocol.equals("https");
        }

        /**
         * Sets the attack payload.
         *
         * @param data A string representing the payload to be sent to the target server.
         */
        public void setData(String data) {
            this.data = data;
        }

        /**
         * Sets the attack type.
         *
         * @param type A string representing one of the two possible attack types.
         *             Parallel - in this mode, a separate connection is created for each request. Requests are sent at the same time (using non-blocking socket write). Optionally, sending a request can be divided into 2 parts. The first is sending the main part of the request, the second is sending the last part of the request, after some time. In the parallel mode, the delay time and the size of the last part can be set.
         *             Pipeline - in this mode, requests are glued together into one large request, which is sent through one connection.
         */
        public synchronized void setType(String type) {
            this.type = type;
        }

        /**
         * Gets the attack type.
         *
         * @return A string representing an attack type.
         **/
        public String getType() {
            return type;
        }

        /**
         * Sets the parallel request sending delay.
         *
         * @param delayTimeUsec A string representing the delay between sending the packets. This option is used only in the parallel mode.
         */
        public void setDelayTimeUsec(String delayTimeUsec) throws NumberFormatException {
            this.delayTimeUsec = Integer.parseInt(delayTimeUsec);
        }

        /**
         * Gets the parallel request sending delay.
         *
         * @return A string representing the delay between sending the packets.
         */
        public int getDelayTimeUsec() {
            return delayTimeUsec;
        }

        /**
         * Sets the size of the last request part.
         *
         * @param last_chunk_size A string representing the size of the last request part. This option is used only in the parallel mode.
         */
        public void setLastChunkSize(String last_chunk_size) throws NumberFormatException {
            this.lastChunkSize = Integer.parseInt(last_chunk_size);
        }

        /**
         * Gets the size of the last request part.
         *
         * @return A string representing the size of the last request part.
         */
        public int getLastChunkSize() {
            return lastChunkSize;
        }

        /**
         * Sets the requests count.
         *
         * @param count A string representing the number of repetitions of sending specified packet.
         */
        public void setCount(String count) throws NumberFormatException {
            this.count = Integer.parseInt(count);
        }

        /**
         * Gets the requests count.
         *
         * @return A string representing the number of repetitions of sending specified packet.
         */
        public int getCount() {
            return count;
        }
    }
}
