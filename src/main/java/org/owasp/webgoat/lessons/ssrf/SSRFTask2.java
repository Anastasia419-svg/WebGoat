/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import java.net.URI;
import java.net.URLConnection;


@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

 protected AttackResult furBall(String url) {
  try {
    URI uri = new URI(url);

    String scheme = uri.getScheme();
    if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
      return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
    }

   
    String host = uri.getHost();
    if (host == null || !host.equalsIgnoreCase("ifconfig.pro")) {
      return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
    }

   
    int port = uri.getPort();
    if (port != -1 && port != 80 && port != 443) {
      return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
    }

    String path = uri.getPath();
    if (path != null && !path.isEmpty() && !path.equals("/")) {
      return getFailedResult("<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">");
    }

    String html;
    URLConnection conn = uri.toURL().openConnection();
    conn.setConnectTimeout(3000);
    conn.setReadTimeout(3000);

   
    conn.setRequestProperty("User-Agent", "WebGoat");
    // για HttpURLConnection θα δουλέψει αυτό:
    if (conn instanceof java.net.HttpURLConnection httpConn) {
      httpConn.setInstanceFollowRedirects(false);
      httpConn.setRequestMethod("GET");
    }

    try (InputStream in = conn.getInputStream()) {
      html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\n", "<br>");
    } catch (IOException e) {
       html =
          "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
              + " this exercise the right way!</body></html>";
    }

    return success(this).feedback("ssrf.success").output(html).build();

  } catch (Exception e) {
    
    var html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
    return getFailedResult(html);
  }
}


  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
