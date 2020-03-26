rule CofenseIntel_CoronavirusPhishing_Indicators {
meta:
  copyright = "/* (c) 2020 Cofense Inc. available at https://cofense.com/solutions/topic/coronavirus-infocenter/   */"
  license = "This yara rule is offered pursuant to the Attribution-NonCommercial-NoDerivatives 4.0 International license, available at https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode."
  
  description = "This yara rule consists of major and actionable indicators that Cofense has identified for phishing emails and related malware that are leveraging the CoronaVirus or Covid-19 theme. This data comes from Cofense's Intelligence team, proprietary data collection sources, and the Cofense Phishing Defense Center. This yara rule should be considered a living rule, and will be updated periodically with new and additional indicators as they are identified and validated by the Cofense Intelligence Team."
  
  author = "Cofense Intelligence, Cofense Labs"
  version = "6"
  known_variants_covered = "37"
  date_created = "17-Mar-2020"
  last_updated = "25-Mar-2020"
  change_log_17Mar2020 = "initial rule creation"
  change_log_19Mar2020 = "added: 4 email addresses, 8 file names, 5 urls, 7 subject lines"
  change_log_20Mar2020 = "added: 7 urls, 4 filenames, 5 subject lines"
  change_log_23Mar2020 = "added: 1 url, 6 filenames, 4 subject lines"
  change_log_24Mar2020 = "added: 6 urls, 3 filenames, 3 subject lines"
  change_log_25Mar2020 = "added: 2 email addresses, 29 urls, 5 filenames, 5 subject lines"

strings:
  $domain1="cornerload.dynu.net" nocase
  $domain2="seasons444.ddns.net" nocase
  $domain3="seasonsnonaco.ddnsking.com" nocase
  $email1="zakir@perfectfashion-bd.com" nocase
  $email2="postmaster@mallinckrodt.xyz" nocase
  $email3="brentpaul403@yandex.ru" nocase
  $email4="dutch@standardbox.space" nocase	
  $email5="info@finazzer.com" nocase	
  $email6="marco.branchi@inbox.lv" nocase	
  $email7="ricardo.ospina@bnb-spa.com" nocase	
  $email8="agarrard@protonmail.com" nocase
  $email9="mercylogs7@yandex.com" nocase

  $url1="https://site-inspection.com/.well-known/acme-challenge/w.php/9SG2m697HN" nocase
  $url2="http://onlinepreneur.id/manager/brain.exe" nocase
  $url3="http://onlinepreneur.id/license/love.exe" nocase
  $url4="https://notmsg.smvm.xyz/" nocase
  $url5="https://toyswithpizzazz.com.au/service/coronavirus/" nocase
  $url6="https://southhillspros.com/Rovince/Jelink.html" nocase
  $url7="https://wusameetings.tk/boding/Jelink.html" nocase
  $url8="https://southhillspros.com/citrix/Ward/broward.php" nocase
  $url9="https://jetluxinc396.sharepoint.com/:b:/g/ERt-r1ZM6PRGhKdxb6bfZSIBcOX2b0y8snN4fg8f7z22rA" nocase
  $url10="https://southhillspros.com/citrix/Ward/broward.htm" nocase
  $url11="https://www.scholarcave.com/owa/owa.php" nocase
  $url12="http://www.dogogiaphat.com/ecdc.php" nocase
  $url13="https://takemorilaw.com/wp-content/micro-update-1-2/" nocase
  $url14="http://my.pcloud.com/publink/show?code=XZO5BWkZjc6l5EBCtnkTYqw2DHqzEBT4LAay" nocase
  $url15="https://www.schooluniformtrading.com.au/cdcgov/files/" nocase
  $url16="https://gocycle.com.au/cdcgov/files/" nocase
  $url17="https://onthefx.com/cd.php" nocase
  $url18="https://urbanandruraldesign.com.au/cdcgov/files/" nocase
  $url19="https://healing-yui223.com/cd.php" nocase
  $url20="https://www.brightparcel.com/corona/owa.php" nocase
  $url21="https://noithatgoocchoav.com/cd.php" nocase
  $url22="http://euromopy.tech/etty/black/download/fre.php" nocase
  $url23="https://drive.google.com/uc?export=download&id=1V8530tZ-SNHELlaVL4BMQpJrRU2DBPSL" nocase
  $url24="http://bit.ly/2TpOpNS" nocase
  $url25="http://edirneli.net/tr/logo.gif" nocase
  $url26="http://185.244.30.4:6669" nocase
  $url27="http://sevgikresi.net/logof.gif" nocase
  $url28="http://natufarma.net/imagens/logof.gif" nocase
  $url29="http://emrahkucukkapdan.com/img/button.gif" nocase
  $url30="https://pastebin.com/raw/vnPLhhBH" nocase
  $url31="http://autocarsalonmobil.com/wp-content/uploads/Internetsonline.txt" nocase
  $url32="http://hidroservbistrita.ro/images/logo.gif" nocase
  $url33="http://krupoonsak.com/logo.gif" nocase
  $url34="http://snsoft.host-ed.me/images/logos.gif" nocase
  $url35="http://gardapalace.it/logo.gif" nocase
  $url36="http://mabdesign.unlugar.com/button.gif" nocase
  $url37="http://nlcfoundation.org/images/xs.jpg" nocase
  $url38="http://glamfromeast.com/image/logo.gif" nocase
  $url39="http://datalinksol.com/logo.gif" nocase
  $url40="http://babystophouse.com/images/logo.gif" nocase
  $url41="http://68.168.222.206/logos.gif" nocase
  $url42="https://185.216.35.10/3/L2KSUN.php" nocase
  $url43="http://uzoclouds.eu/dutchz/dutchz.exe" nocase
  $url44="http://posqit.net/TT/50590113.exe" nocase
  $url45="http://bitly.ws/83FN" nocase
  $url46="https://marsdefenseandscience.com/reports.zip" nocase
  $url47="https://eabi7yab.appspot.com/app.php" nocase
  $url48="https://eabi7yab.appspot.com/" nocase
  $url49="https://sway.office.com/ggKC030OqLgA59rj?ref=Link" nocase
  $url50="http://tidy-saiki-6718.deci.jp/MIY/MLY.exe" nocase
  $url51="http://academydea.com/alhaji/Panel/five/fre.php" nocase
  $url52="https://saltcitymktg.com/ssl/?0@=" nocase
  $url53="http://tonpr.esy.es/http/Office/SSL/Login/cmd-login=" nocase
  $url54="http://192.3.31.212/TickCountnrKDyhvMKK.exe" nocase
  $url55="http://posqit.net/GE/5091203.jpg" nocase
  $url56="http://bit.ly/2J9KXAM" nocase
  $url57="https://www.hb-bonusclaim.com/hotelier/bonuses/vlar/oie/qwol/Sign_In_password.php" nocase
  $url58="https://www.hb-bonusclaim.com/hotelier/bonuses/vlar/oie/qwol" nocase
  $url59="https://goldenlion.sg/blacky2/hQFMCdSYQ81nUlp.exe" nocase
  $url60="https://netorgft6251601-my.sharepoint.com/personal/remote_enrollopen_com/_layouts/15/" nocase
  $url61="https://bluemediappc.ru/cxsw/?activity=4789652" nocase
  $url62="hxxps://coronasdeflores.cl/who/" nocase
  $url63="hxxps://coronasdeflores.cl/who/files/" nocase
  $url64="hxxps://ee-cop.co.uk/who/" nocase 
  $url65="https://ee-cop.co.uk/who/files/" nocase
  $url66="https://ee-cop.co.uk/who/files/3b9f575dac9cc432873f6165c9bed507.php" nocase
  $url67="https://heinrichgrp.com/who" nocase
  $url68="https://heinrichgrp.com/who/files/" nocase
  $url69="https://heinrichgrp.com/who/files/af1fd55c21fdb935bd71ead7acc353d7.php" nocase
  $url70="https://mykipay.com/who/" nocase
  $url71="https://mykipay.com/who/files/" nocase
  $url72="https://o.splashmath.com/ls/click?upn=H2FOwAYY7ZayaWl4grkl1LazPuy6jduhWjWPwf0O2D" nocase
  $url73="https://o.splashmath.com/ls/click?upn=msxJtQrcMkxf-2FHgHZWqFOpZY87uOjW56A4EtZK629w" nocase
  $url74="https://o.splashmath.com/ls/click?upn=YtJZYRNKQgIuqGqUou2Wawk1LrccW6qSlY" nocase
  $url75="https://pharmadrugdirect.com/who/" nocase
  $url76="https://pharmadrugdirect.com/who/files/" nocase
  $url77="https://url885.whoint.us/ls/click?upn=" nocase
  $url78="https://www.bangkukuliah.com/who/" nocase
  $url79="https://www.bangkukuliah.com/who/files/" nocase
  $url80="https://www.enciety.co/who/" nocase
  $url81="https://www.enciety.co/who/files/" nocase
  $url82="https://www.whtextiles.com.pk/who/files/" nocase
  $url83="https://www.whtextiles.com.pk/who/" nocase
  $url84="https://www.frufc.net/who/files/61fe6624ec1fcc7cac629546fc9f25c3.php" nocase
  $url85="https://www.frufc.net/who/files/" nocase
  $url86="https://www.frufc.net/who/" nocase
  $url87="https://goldenlion.sg/blacky2/QcxbDp400Ajfdiy.exe" nocase
  $url88="http://mecharnise.ir/ca17/ca17.exe" nocase
  $url89="https://jstforyou.com/agenda.zip" nocase
  
  $filename1="CoVid19_BAH.PDF.tar" nocase
  $filename2="CORONA TREATMENT.doc" nocase
  $filename3="CORONA VIRUS REMEDY ISREAL.doc" nocase
  $filename4="SAFETY PRECAUTIONS.rar" nocase
  $filename5="5567688.htm" nocase
  $filename6="Employee Survey.pdf" nocase
  $filename7="DOWNLOAD-COVID-19-REPORT-SAFETY.doc.iso" nocase
  $filename8="Internetsonline.txt" nocase
  $filename9="Rapport sur les coronavirus.doc" nocase
  $filename11="Info_17031267613.doc" nocase
  $filename12="Info_17031267690.doc" nocase
  $filename13="Info_17033267636.doc" nocase
  $filename14="Info_1989267740.doc" nocase
  $filename15="UPDATE!!!.xlsx" nocase
  $filename16="COVID-19.zip" nocase
  $filename17="COVID-19 WHO RECOMENDED V.gz" nocase
  $filename18="50590113.xlam" nocase
  $filename19="CORONAVIRUS.XLSX" nocase
  $filename20="MLY.exe" nocase
  $filename21="covid51_form.zip" nocase
  $filename22="covid51_form.vbs" nocase
  $filename23="PKQL-7263913.exe" nocase
  $filename24="Attachment.iso" nocase
  $filename25="Emergency Funds Document.exe" nocase
  $filename26="COVID-19 Precautions.doc" nocase
  $filename27="covid49_form.vbs" nocase
  $filename28="covid49_form.zip" nocase
  $filename29="COSCO WORKING PLAN.xlsm" nocase
  $filename30="COVID 19 NEW ORDER FACE MASKS.doc" nocase
  $filename31="covid 19.rtf" nocase
  $filename32="COVID - 19 Treatment & Cure.pptx" nocase
  $filename33="WxByN.xlsm" nocase
  $filename34="Sample Products.xlsx" nocase
  $filename35="Covid-19 Immunity Diet Tips.pdf.exe" nocase
  $filename36="Covid-19 Immunity Diet Tips.pdf.zip" nocase
  
  $subject1="[Newsletter] Coronavirus (COVID-19) new cases confirmed in your city" nocase
  $subject2="[Newsletter] Coronavirus: Important update" nocase
  $subject3="Attention: List Of Companies Affected With Coronavirus March 02, 2020" nocase
  $subject4="CORONA VIRUS CURE FOR CHINA,ITALY" nocase
  $subject5="Coronas Virus Reached 3 more cities in United States" nocase
  $subject6="Coronavirus (COVID-19) new cases confirmed in your city" nocase
  $subject7="Coronavirus: Important update" nocase
  $subject8="COVID-19 - Now Airborne, Increased Community Transmission" nocase
  $subject9="FW: Corona Virus (Covid-19 / 2019-nCoV) Impact to Sea freight Supply Chains" nocase
  $subject10="Rapport de transmission du coronavirus du AIRFRANCE/KLM" nocase
  $subject11="RE: IT-Service desk: Coronavirus notice for all employee" nocase
  $subject12="RE:CORONA VIRUS CURE FROM ISREAL" nocase
  $subject13="Restrictions - Update on Coronavirus" nocase
  $subject14="URGENT ATTENTION/COVID-19/CASE-REPORT/SAFETY" nocase
  $subject15="Urgent Corona Virus Employee Survey" nocase
  $subject16="RE: Coronavirus disease (COVID-19) outbreak prevention and cure update." nocase
  $subject17="Coronavirus: an important information about precautionary measures for the enterprises" nocase
  $subject18="Fw:UN" nocase
  $subject19="Corona Virus update" nocase
  $subject20="World Health Organization/ Let's fight Corona Virus together" nocase
  $subject21="Mask supply and Vaccine for virus" nocase
  $subject22="March General Meeting (Coronavirus)" nocase
  $subject23="Recent Matters Addressed On Covid-19 And World Food Imports." nocase
  $subject24="Participation in the procurement of logistics of Corona Virus" nocase
  $subject25="CORONAVIRUS (COVID-19) UPDATE // BUSINESS CONTINUITY PLAN ANNOUNCEMENT STARTIN" nocase
  $subject26="Information about COVID-19 in the United States" nocase
  $subject27="Re: Coronavirus Review for " nocase
  $subject28="Emergenza COVID 19 / COVID 19 emergency" nocase
  $subject29="Covid-19 Emergency funds Update" nocase
  $subject30="COSCO SHIPPING KOERA - working plan, COVID-19 Precautions" nocase
  $subject31="Coronavirus: All 50 States Report Cases" nocase
  $subject32="COVID:19 - FACIAL MASKS NEW ORDER" nocase
  $subject33="Information about Covid- 19 Actions" nocase
  $subject34="Work Remotely Enrollment (Action Required)" nocase
  $subject35="(CDC) Approved Treatment & Cure" nocase
  $subject36="HIGH-RISK: New confirmed cases in your city" nocase
  $subject37="Information about Covid- 19 Actions" nocase
  $subject38="COVID-19 Supplies (Masks, Gloves, & other products)" nocase
  $subject39="RE: Covid19\" Latest Tips to stay Immune to Virus !!" nocase
  
  condition:
    any of them
}