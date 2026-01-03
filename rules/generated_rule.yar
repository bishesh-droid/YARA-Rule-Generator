rule GeneratedMalwareRule
{
    meta:
        author = "YARA Rule Generator"
        date = "2026-01-03"
        description = "Automatically generated rule for GeneratedMalwareRule"

    strings:
        $s0 = "evil_string_goes_here"

    condition:
        all of ($s0)
}