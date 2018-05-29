# GoogleAuthenticator
[![Language](https://img.shields.io/badge/Lang-Java-blue.svg)](https://www.java.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-red.svg)](https://opensource.org/licenses/Apache-2.0)

## A Burp Suite extension to set up macro using Google 2FA code.

## Installation
### Compilation 
#### Windows & Linux
1. Install gradle (<https://gradle.org/>)
2. Download the repository.
```shell
$ git clone https://github.com/AresS31/GoogleAuthenticator
$ cd .\GoogleAuthenticator\
```
3. Create the jarfile:
```shell
$ gradle fatJar
```

### Burp Suite settings
In the Burp Suite, under the `Extender/Options` tab, click on the `Add` button and load the `GoogleAuthenticator-all` jarfile. 

## Possible Improvements
- [ ] Add new features.
- [ ] Improve the UI.
- [ ] Source code optimisation.

## License
Copyright (C) 2018 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
