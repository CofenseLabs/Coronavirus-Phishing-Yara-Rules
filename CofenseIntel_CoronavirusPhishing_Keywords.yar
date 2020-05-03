rule CofenseIntel_CoronavirusPhishing_Keywords {
meta:
  copyright = "/* (c) 2020 Cofense Inc. available at https://cofense.com/solutions/topic/coronavirus-infocenter/   */"
  license = "This yara rule is offered pursuant to the Attribution-NonCommercial-NoDerivatives 4.0 International license, available at https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode."
  
  description = "This yara rule consists of the most popular and widely overlapping keywords and phrases seen by Cofense across thousands of Coronavirus or Covid-19 related phishing emails. This rule should be considered as an enrichment rule to highlight Coronavirus/Covid-19 related emails, some of which may not be malicious. Due to the increasing volume and quantity of phishing templates using these themes, this rule is being marked as a Priority 5. This data comes from Cofense's Intelligence team, proprietary data collection sources, and the Cofense Phishing Defense Center. This yara rule should be considered a living rule, and will be updated periodically with new and additional indicators as they are identified and validated by the Cofense Intelligence Team."

  author = "Cofense Intelligence, Cofense Labs"
  version = "1"
  date_created = "23-Mar-2020"
  change_log_23Mar2020 = "initial rule creation"
  
strings:
  $c1 = " corona" nocase
  $c2 = " covid" nocase
  $c3 = "codiv-19" nocase
  $c4 = "wuhan" nocase
  $lure1 = "attached" nocase
  $lure2 = "invoice" nocase
  $lure3 = "PO"
  $lure4 = "document" nocase
  $lure5 = "click" nocase
  $lure6 = "we have provided an updated" nocase
  $lure7 = "community spread" nocase
  $lure8 = "world health organization" nocase
  $lure9 = "covid-19 update" nocase
  $lure10 = "face mask" nocase
  $lure11 = " update" nocase
  $lure12 = "outbreak" nocase
  
condition:
  1 of ($c*) and 1 of ($lure*)
}
