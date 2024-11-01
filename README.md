# OwnHaystack (Macless OpenHaystack + Owntracks)

This project is meant as a simpler alternative to [Macless-Haystack](https://github.com/dchristl/macless-haystack),
by focusing on its main competency: getting position reports from Apple's FindMy Network.

It doesn't include its own frontend, but is meant to be used in conjunction with an MQTT broker
and [OwnTracks](https://owntracks.org/booklet/guide/whathow/). All this project does is collecting position reports,
decrypting them and publishing them to an MQTT broker in
a [standardized format](https://owntracks.org/booklet/tech/json/#_typelocation).

## Setup

This is meant as a fully featured and easy jumping off point, by also including the setup for an MQTT broker, as well as
the [OwnTracks Recorder](https://owntracks.org/booklet/clients/recorder/) as a frontend.

0. Make sure Docker and Docker Compose are installed on your system
1. Download the [`compose.yaml`](compose.yaml) file
2. Replace `${APPLE_USERNAME}` and `${APPLE_PASSWORD}` with your login data
3. Setup the tags with their keys
    1. Depending on your hardware follow the instructions
       for [ESP32](https://github.com/dchristl/macless-haystack/tree/main/firmware/ESP32),
       [nrf5x](https://github.com/dchristl/macless-haystack/tree/main/firmware/nrf5x)
       or [Flipper Zero](https://github.com/MatthewKuKanich/FindMyFlipper/tree/main?tab=readme-ov-file#step-by-step-instructions)
    2. For every tag create a `.priv_keys` file in the `./data/keys` folder containing one base64 enecoded private key
       per line.
       (Multiple lines are only needed if you are using rotating keys on the device.)
    3. The filename of the file will be used as the mqtt topic and name of the tag. E.g., `flipper.priv_keys` will result
       in its position reports to be posted to `owntracks/haystack/flipper`
4. Start the container in interactive mode with `docker-compose run --rm haystack`
5. Enter your 2FA code when you are asked for it
6. Once you have sucessfully authenticated the 2FA, a `auth.json` file is created and you should be able to start the
   container normally
7. Goto [`http://localhost:8083/`](http://localhost:8083/) to see the OwnTracks frontend with the captured location
   reports

# Config

All of this projects features are configured through environment variables:

| Variable          | Default                                                                | Description                                                            |
|-------------------|------------------------------------------------------------------------|------------------------------------------------------------------------|
| APPLE_USERNAME    | *required*                                                             | The email of your Apple ID                                             |
| APPLE_PASSWORD    | *required*                                                             | The password of your Apple ID                                          |
| TRUSTED_DEVICE    | `False`                                                                | Set to `TRUE` if a Trusted Device should be used for 2FA instad of SMS |
| ANISETTE_URL      | [dynamic public server](https://github.com/SideStore/anisette-servers) | URL to an anisette server (including `http`/`https`)                   |
| MQTT_TOPIC_PREFIX | `owntracks/haystack/`                                                  | Where to post the location records                                     |
| MQTT_SERVER       | *required*                                                             | Hostname or IP of MQTT broker                                          |
| MQTT_PORT         | `1883`                                                                 | MQTT port number                                                       |
| MQTT_USERNAME     | *no auth*                                                              | MQTT username                                                          |
| MQTT_PASSWORD     | *no auth*                                                              | MQTT password                                                          |
| MQTT_TLS          | `FALSE`                                                                | Set to `True` if MQTT over TLS should be used                          |
| REFRESH_INTERVAL  | `5`                                                                    | Time in minutes between updating the locations from the FindMy network |
| AUTH_FILE         | `\data\auth.json` in docker<br/>`.\data\auth.json` otherwise           | Location of the auth file                                              |
| KEY_FOLDER        | `\data\keys` in docker<br/>`.\data\keys` otherwise                     | Location of the private key files                                      |

# Previous Work

This project is based on: (Credits go to them for the hard work)

- [FindMyFlipper](https://github.com/MatthewKuKanich/FindMyFlipper)
    - For most of the code connecting to Apple's servers and decrypting the reports
- [Macless-Haystack](https://github.com/dchristl/macless-haystack)
    - For the Firmewares and Key Generation
    - which in turn is also based on:
        - [Openhaystack](https://github.com/seemoo-lab/openhaystack)
        - [Biemster's FindMy](https://github.com/biemster/FindMy)
        - [Positive security's Find you](https://github.com/positive-security/find-you)
        - [acalatrava's OpenHaystack-Fimware alternative](https://github.com/acalatrava/openhaystack-firmware)
