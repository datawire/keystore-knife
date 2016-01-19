package io.datawire.keystoreknife.command;


import com.google.common.io.BaseEncoding;
import io.datawire.app.Initializer;
import io.datawire.app.command.Command;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileWriter;

public class GenerateKeyCommand extends Command {

  public GenerateKeyCommand() {
    super("generate-mac-secret", "Generate a secret key for use with MAC");
  }

  @Override
  public void configure(Subparser subparser) {
    subparser.addArgument("algorithm")
        .help("The algorithm to use for key generation")
        .choices("HmacSHA256", "HmacSHA384", "HmacSHA512");

    subparser.addArgument("--format")
        .help("The output format")
        .choices("json", "line")
        .setDefault("line");

    subparser.addArgument("--output-file")
        .help("The file to write the result into")
        .type(Arguments.fileType());
  }

  @Override
  public void run(Initializer<?> initializer, Namespace namespace) throws Exception {
    KeyGenerator keygen = KeyGenerator.getInstance(namespace.getString("algorithm"));
    SecretKey secretKey = keygen.generateKey();

    byte[] encoded = secretKey.getEncoded();

    String base64 = BaseEncoding.base64().encode(encoded);
    String base64UrlSafe = BaseEncoding.base64Url().encode(encoded);
    String base16 = BaseEncoding.base16().encode(encoded);

    String format = namespace.getString("format");
    String output = null;
    switch (format.toLowerCase()) {
      case "json":
        output = buildJsonFormat(base64, base64UrlSafe, base16);
        break;
      case "line":
      default:
        output = buildLineFormat(base64, base64UrlSafe, base16);
        break;
    }

    File outputFile = namespace.get("output_file");
    if (outputFile != null) {
      try(FileWriter writer = new FileWriter(outputFile)) {
        writer.write(output);
      }
    } else {
      System.out.println(output);
    }
  }

  private String buildJsonFormat(String base64, String base64UrlSafe, String base16) {
    StringBuilder result = new StringBuilder("{").append(System.lineSeparator());
    result.append("  \"base 16\": ").append('"').append(base16).append("\",").append(System.lineSeparator());
    result.append("  \"base 64\": ").append('"').append(base64).append("\",").append(System.lineSeparator());
    result.append("  \"base 64 (url safe)\": ").append('"').append(base64UrlSafe).append('"').append(System.lineSeparator());
    result.append("}");
    return result.toString();
  }

  private String buildLineFormat(String base64, String base64UrlSafe, String base16) {
    StringBuilder result = new StringBuilder();
    result.append("base 16       -> ").append(base16).append(System.lineSeparator());;
    result.append("base 64       -> ").append(base64).append(System.lineSeparator());;
    result.append("base 64 (url) -> ").append(base64UrlSafe).append(System.lineSeparator());;
    return result.toString();
  }
}
