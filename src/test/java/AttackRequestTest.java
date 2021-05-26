import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import static org.junit.jupiter.api.Assertions.*;

import burp.model.AttackRequest;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AttackRequestTest {
    private AttackRequest defaultConfig;

    @BeforeAll
    private void prepareIt() {
        defaultConfig = new AttackRequest.RequestBuilder().build();
    }

    @Test
    public void testDefaultBuildersMatching() {
        AttackRequest configFromString = new AttackRequest.RequestBuilder().with(defaultConfig.getJsonConfig());
        assertEquals(defaultConfig.getJsonConfig(), configFromString.getJsonConfig(),
                "Default builders cannot be different: \n" + defaultConfig + "\n" + configFromString);
    }
}