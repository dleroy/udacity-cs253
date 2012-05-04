#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi

form="""
<form method="post">
  <label> Text to be rotated
     <input type="textarea" name="text">
  </label>
  <br>
  <br>
  <input type="submit">
</form>
"""

def rot13(s):
    if s:
       return s.encode('rot13')

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(form)

    def post(self):
        in_text = self.request.get("text")
        out_text = cgi.escape(rot13(in_text))
        self.response.out.write(out_text)

app = webapp2.WSGIApplication([('/', MainHandler)],
                              debug=True)
