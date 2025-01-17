//  Copyright (c) 2021 D4L data4life gGmbH
//  All rights reserved.
//
//  D4L owns all legal rights, title and interest in and to the Software Development Kit ("SDK"),
//  including any intellectual property rights that subsist in the SDK.
//
//  The SDK and its documentation may be accessed and used for viewing/review purposes only.
//  Any usage of the SDK for other purposes, including usage for the development of
//  applications/third-party applications shall require the conclusion of a license agreement
//  between you and D4L.
//
//  If you are interested in licensing the SDK for your own applications/third-party
//  applications and/or if you’d like to contribute to the development of the SDK, please
//  contact D4L by email to help@data4life.care.
//

import Foundation

enum Fixture {
    static let privatePEM = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8JyGJuwH8j2nY
tNTIHawVEXHrFogYLbBzCLEG80dD3Jp1zudqqwdbArytGKIwKMJUfmTa+n54L5vb
z/EwqsWxc/Wct8RUSN5tpkQvK4TjWgFJzsWRLv0rv+e1gTfQn4e/Q+JXWubsFBKl
ZFMXGRznnbNgKT9TGpKuGuO6ukrY0WXbeRX4Rd6NDbhzoexA1C8WltYccij5+tGf
zyTA1B+60EgJkF6gV5FtoYNEZAQKPtswGSSmAaZLzioVUeQTt2ICFJw4lZfc0dTG
HUQIvvc2UwXn2A3mC6/rwi4Q67U+AVUQKpu+Am8NXKjcy/0wV/3WjBriLrBAXcv2
va/lFmKLAgMBAAECggEAMmQIh2qeTZXbMz66/h10SPAzIlMWf+M8rpJVVxcwruwW
MhcHw3mqrqU9At7mER/Za+et+ze7R1T42RYH8pDKAYyc6ywMWMZrS9KL0FZHcNxa
G/pUz11WULFEzUeeOzF+masEo4Ck9/UoSUNlPXpsU1vY/pgNbaRgRGDPPONHyGlW
2eJDuajtEtPrEB2MqdKYG3yk8LXiMIS2SQZtHpWAsAhvp1s4whLroQBxyhEwwuNw
CwoI6knc1rcfrxspkaW5q2eZCMF0fWK84PdZ9rDcaSZwUJfMPCETW33C9NXVCLdD
Yw0xihRUxyXcS4tqU+DZk3X0UfuTIdMEnPS+OpfMAQKBgQDft8ZElLjHWyF9M2dv
ywvaICmRmPF32sW5eEfaR/J8bR1ZOAUI5/dZv/rpm7X8I2dWn5qQLB+ka//AkHia
KXRYRGsdWk8YIZI/1VFxpXkzK/f+mtM7kv2KJVBhhgI0siMT4miNirlQHzcbmouJ
/xwXuyCsg1rNDtflqJ8FK2DR6wKBgQDXTZIuj3jsUWmUGogCiWVbhlfKvITZokHU
gw4V5Gx//B833UmGTJ/1lEV671h2OShzyNJMxTgDu5O+mxfv4hq8A6cY4hbu1Fii
p7EPF0V8t+/GyjeB/XMzl/0jyGRXQxzaWSe8Lv/cfM9j7tQVY/G58EEULR9sN0R2
wfcQtw3p4QKBgGHmIt5KEp4ys/H896vFN/eJEYfEXQ6s7s+d4huUVnm6qhgr2pAu
KmDdESj/WeDvgT4388RZerNSC4Yx8oTL1Tz3G8Spi2ks77n9WHmaBvKssAZ7rCoq
xcaZU5aJtRdoSM9fyY7/AN8d+dibhaqqt5lu6vpzNN39O98lLgluFR1nAoGAGAV/
mdJIG5W5wdxz8FSECoIiqWv/JokD70HwAGFL+buXgBQgb+t8rVmtptmtdQNLkB+H
1yjp5wC2qz2CnjEL6o49xnjzNhJbEUrEZnqiNhgPmI5XQxmUEN2UULm6+EF0pqfr
1wMnaOJEAVJUN06/WY+Es0uVhe1kphteBW9nDgECgYBp9auG5WYcjkt43KCBZxSn
PIEo0wnUVl0rQaMt69/bfulwX/zN4M4tdhqjY//LsNMWc2e8F/OJtghRmGzHkCYL
ILd1QNqqi0waaNvC8kdnUssO3jStEm1+6wzfyVoVB5cl8ob36vEzwwC8lLtyUjFt
rYl/vFV+gqGGJPzR7EqiGw==
-----END PRIVATE KEY-----
"""

    static let publicPEM = """
        -----BEGIN KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvCchibsB/I9p2LTUyB2s
        FRFx6xaIGC2wcwixBvNHQ9yadc7naqsHWwK8rRiiMCjCVH5k2vp+eC+b28/xMKrF
        sXP1nLfEVEjebaZELyuE41oBSc7FkS79K7/ntYE30J+Hv0PiV1rm7BQSpWRTFxkc
        552zYCk/UxqSrhrjurpK2NFl23kV+EXejQ24c6HsQNQvFpbWHHIo+frRn88kwNQf
        utBICZBeoFeRbaGDRGQECj7bMBkkpgGmS84qFVHkE7diAhScOJWX3NHUxh1ECL73
        NlMF59gN5guv68IuEOu1PgFVECqbvgJvDVyo3Mv9MFf91owa4i6wQF3L9r2v5RZi
        iwIDAQAB
        -----END KEY-----
        """

    static let privateEncryptedPEMAES128 = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,905D8CE3C9878467D460F9C0F2B5FEF3
        vNM1pO9DlnfOEtHgeNZkLAydL1UnU2Q5tnq/x8uEovaJZCEwWOaUe+p9A2w4E/fl
        57xzgwofj7jZcDIc2eAkAzwQju9RdhctO8d5CMHCfqAf7uKqeTLG1f4y2eWYvvYM
        /a5ZZZ5RFfJ/yDUf2LE301L0lLCoNwZ1o3cLou+TUeC3Z4ClxL16lIyy5E+Gi4W4
        NNtNZlj2jfBIY/zlwcAO7BvQysUhJgXHTUEwzJW0cOVmow8vqBy7oijtYqkVnqHZ
        g2SnL0w6pUe9gAfO869rUOdUcStOBdbnkmDV16iVglb8fE5VXCtnBQ9nN3tXpKum
        n3hTEd6qyYINhKnGKd+E+1eWEHF2cfEBoN3rHe8FKrsFF3dd9R0Q3UqOQppt4lF+
        M8Gjd+GJbypAaBOrnRcIXfnVZNUYLDZ4O68qvc3ewsF/A3T7drA9riBxPUxDN41x
        TtluCO7azZqn8FaY/Rfj6it3NcDW5UrM2TJPT3Gb/LtTaSqu4lD8p8VtfHxbOTyn
        3tWRBFYRA86JSp7WsCQJEVgyOrTPeJgSZwUUwaSROFNWv2In3gmAX5l8wPGzwBOw
        EOQLf8qT5gyt34fuc0IawkLKfGsG6lenS9NRorVjWzkdh8Aw4ooRfM67omglPtN7
        VFj2Z6mhPaVHUBYKfrnSQMhGmPQxueQhlDBPyo74SinbJ1xFD9xjvM1bT8jlfVdF
        VGu0fBV1r2oY+Q3dn0z0sxVbUOJv9SlATj6kQmfShlw9cbpuUYWjCnPrM2hN37Q4
        7P0nXRSy3+N6RpGX/uAyK9yTM4R8uD7f2WeDSVBzoDd9gUeNk/5UGd++X7DYdaFK
        dzi2KMOhoKioIoj1pey+dybcL60nq+92MG9OyIjW6syLRsW0oZByMZVDBAnv5tVu
        RpcM4jiHWCmosguBA2t0YaeXSaEsJI7jHJU/fG1NUK6eHPO3gTaLC6B0Ru3okW+W
        fgqT7VM81SzuJo1xHKoZ756cetSEzHi2IN4xQjdJ9EZQoQhBzqlcQyW5eYT+t8FA
        I67alFYVzsUNYOy8fCqPvganzOESX75Zc6gOdgHb4ti9o2B0lnFjd0rkcZvfqqM4
        t/HkrJWPY5CjI/yaF/lgM1bNcRL84I8rScMePfPJPByaB+rIs6LYv2LFvyBQoWMx
        oOh8fRQ0zqrgqQBtEwFNvv8xL5voAxDrtH9Tg25/BsPeulx+5HyeQFBVoEq90Tws
        qa8/immZQZOqazrgGopA7vL1JWN00vzfXWdUZfXrO1PlhM7v/ploOtTRHTlUH0wO
        P0mVZCUugxfuG2jgZGUB2Ckl8Wkm91S68EBesAsk9urWjxusSDTDMfkevoUCBBwB
        A3X42p14L02F4mLIINUvKUb5OrcQMEABI/dgXlESA+Q3kA5o10Us/Mfogtq6JPyh
        VtTciLSWf9h54ndY0pxpL0Gzhx14ptqVB9gI9vQIrdh2ArjclV7Pr2lFUt6onYEa
        sfptyO+nuDF7Q2m09P6X/W9xo+R8UuGOaNYsaJzcymERkHfJx2BAbcO/NSn+cha2
        To40Cs1EUiXmX4WmONhdAEZprPF1ZWFEaZjyQ0kY7Ys9HHzEYfXOu9+7boNJ1rJG
        -----END RSA PRIVATE KEY-----
        """

    static let privateDecryptedPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEAvCchibsB/I9p2LTUyB2sFRFx6xaIGC2wcwixBvNHQ9yadc7n
        aqsHWwK8rRiiMCjCVH5k2vp+eC+b28/xMKrFsXP1nLfEVEjebaZELyuE41oBSc7F
        kS79K7/ntYE30J+Hv0PiV1rm7BQSpWRTFxkc552zYCk/UxqSrhrjurpK2NFl23kV
        +EXejQ24c6HsQNQvFpbWHHIo+frRn88kwNQfutBICZBeoFeRbaGDRGQECj7bMBkk
        pgGmS84qFVHkE7diAhScOJWX3NHUxh1ECL73NlMF59gN5guv68IuEOu1PgFVECqb
        vgJvDVyo3Mv9MFf91owa4i6wQF3L9r2v5RZiiwIDAQABAoIBADJkCIdqnk2V2zM+
        uv4ddEjwMyJTFn/jPK6SVVcXMK7sFjIXB8N5qq6lPQLe5hEf2Wvnrfs3u0dU+NkW
        B/KQygGMnOssDFjGa0vSi9BWR3DcWhv6VM9dVlCxRM1HnjsxfpmrBKOApPf1KElD
        ZT16bFNb2P6YDW2kYERgzzzjR8hpVtniQ7mo7RLT6xAdjKnSmBt8pPC14jCEtkkG
        bR6VgLAIb6dbOMIS66EAccoRMMLjcAsKCOpJ3Na3H68bKZGluatnmQjBdH1ivOD3
        Wfaw3GkmcFCXzDwhE1t9wvTV1Qi3Q2MNMYoUVMcl3EuLalPg2ZN19FH7kyHTBJz0
        vjqXzAECgYEA37fGRJS4x1shfTNnb8sL2iApkZjxd9rFuXhH2kfyfG0dWTgFCOf3
        Wb/66Zu1/CNnVp+akCwfpGv/wJB4mil0WERrHVpPGCGSP9VRcaV5Myv3/prTO5L9
        iiVQYYYCNLIjE+JojYq5UB83G5qLif8cF7sgrINazQ7X5aifBStg0esCgYEA102S
        Lo947FFplBqIAollW4ZXyryE2aJB1IMOFeRsf/wfN91Jhkyf9ZRFeu9Ydjkoc8jS
        TMU4A7uTvpsX7+IavAOnGOIW7tRYoqexDxdFfLfvxso3gf1zM5f9I8hkV0Mc2lkn
        vC7/3HzPY+7UFWPxufBBFC0fbDdEdsH3ELcN6eECgYBh5iLeShKeMrPx/PerxTf3
        iRGHxF0OrO7PneIblFZ5uqoYK9qQLipg3REo/1ng74E+N/PEWXqzUguGMfKEy9U8
        9xvEqYtpLO+5/Vh5mgbyrLAGe6wqKsXGmVOWibUXaEjPX8mO/wDfHfnYm4WqqreZ
        bur6czTd/TvfJS4JbhUdZwKBgBgFf5nSSBuVucHcc/BUhAqCIqlr/yaJA+9B8ABh
        S/m7l4AUIG/rfK1ZrabZrXUDS5Afh9co6ecAtqs9gp4xC+qOPcZ48zYSWxFKxGZ6
        ojYYD5iOV0MZlBDdlFC5uvhBdKan69cDJ2jiRAFSVDdOv1mPhLNLlYXtZKYbXgVv
        Zw4BAoGAafWrhuVmHI5LeNyggWcUpzyBKNMJ1FZdK0GjLevf237pcF/8zeDOLXYa
        o2P/y7DTFnNnvBfzibYIUZhsx5AmCyC3dUDaqotMGmjbwvJHZ1LLDt40rRJtfusM
        38laFQeXJfKG9+rxM8MAvJS7clIxba2Jf7xVfoKhhiT80exKohs=
        -----END RSA PRIVATE KEY-----
        """

    static let privateEncryptedPEMAES256 = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-CBC,CBB159E4726DD83B543567ABDA2D2FAF
        CNLqaMdh140G6f8ifml1F14JCg7rupUABXFwT/A4LSImZ77exUu7qjf36zBOZeaJ
        A3vIeucb7xC1X9Hp8VWaQRAniDMBJEERf0GRoA2/o8PMz9bSAN/KLhONTpdrtBoy
        af1L6xaOxzIUFJCS53jXQnWnf8dDFQYHSzIeaV6K6yQG2qB5ouJ3iguAlc2AzjSz
        wLskOs2HIy0iIBaQC5pXR1UdagsXEm776ksEUNa5wd0++eXhorDJtOYQK5I8PUXs
        ndAVwAd5f4pXL7CYfputPjEHOFXLcL1En5VGGlKcA9k+qEUmCJeuTQmOZM0giJOF
        8lODv4qZRn4TPm1UJlvXTgl6QVRaoDnuNf++XwVIFgPEWfpr2iBJ0hBeurfJxSjB
        wRBKao6MSrkb5KnZE+9Ccx+8E/qkfn/Lkw9A3UnPjS8pyGoh6SycvP5mJfC6WuXh
        8O4ETgBF595RF/GreAHIK31YmUjVIebxPguYXxNcqTFPu0UMSN/QMhe6qg8kLkZ0
        ZJjVuMJ4EyAaLW9xUQi7k5ynTGvQN0uZwdndrLZPXxgMJR4kM0kN06ex6um2Wvww
        fpRDANG8x9Jpp+c3dqDWVIH8afUI3T4dUGnu2wNpaxJsJGhZqu3wXMPk/23IezTX
        81EONi8hEnWS9iXRGYF8bjZhPwQD8kU7Bw++VbhlW3DydifLpfoap48+nXN/vmlQ
        jODNPR4E47jXPMC+t+6R5esYMaSVj0s5C/WnRrz3sjh/Py01WsenPeSnvyivrl5I
        3JGMH4VJd58Ygy33gmnJ3wLfcMLinPMYq8XMqvhJMDQY/oAZo6a6EZTZNr6zdwQU
        gkv13AK1jPZFczydzfGel8Ru+FD4mARQzjlBwA4akAJgaoQk4NFrOzXZyboFToK2
        4ulGCpKe3U+BZAZUotV3wXbi9bOoa6l/fH+tmribbOv51pSs+aiH60s4BAoqGA+v
        41pwwROsdy/TNX1JqMeYNMRkFvFLNBQFlrwSJuwvPqeJyaV6KHzPQ3TnwuboHowk
        Vw5NxhNHgjNRxzH909uJjzGiZ1EpFh2rbWlMg1QlZg5Dqhzye9k3VxmPwmKeRqPH
        9TRKiKGprOzR11Ontns6y6OTxOsPMwwRUeu3KOuv4b5ZsjrSS5/6nbKBqscX83zL
        DJthtC55XrENOAetatZBSzKwPd0ZeANQcoetZaV3DEm1+YVHlN+NUzLZzgqT33sC
        Nt91zpJn5F8qhyw/jxpAAeyByBjL1s8+jRsRbNiybKiQOP5XO5MTxDiiSGLkzfqk
        LpuF2k2fHRMJdO2YfHT1wurAlMlkVDYiv1Z5zBgTkTc0Kgryc5apAf18uSzxV70d
        AlcCCHqJ7X72L6Cd0fQ80nAT+hHzs3djN3+AQrdj3hNVsO8bcELe4WlZq58WVdmJ
        5sntXhLWqUAHV+ybSVb0XbDbESvw9ugydDmJgJda1eHTPfekEl1tekU63W2EDbr3
        virNS3vBL6AUZsDARR5bV3Koie1zuFuouG0IMoHC3dPkxK/lovokEr69qj37BFOF
        PiMuzVzGugcz4JHCirzbpQOn1mL51FqBj7hVTdMA8u6IqN0OzESM95U6ZZTuwNgP
        -----END RSA PRIVATE KEY-----
        """
}
