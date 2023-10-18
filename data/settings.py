virustotal_throttling = 5
virustotal_retry = 3
apivoid_retry = 3

categories_blacklist = [
    "ADULT_SEX_EDUCATION",
    "ADULT_THEMES",
    "K_12_SEX_EDUCATION",
    "LINGERIE_BIKINI",
    "NUDITY",
    "OTHER_ADULT_MATERIAL",
    "PORNOGRAPHY",
    "SEXUALITY",
    "SOCIAL_ADULT",
    "MARIJUANA",
    "OTHER_DRUGS",
    "GAMBLING",
    "OTHER_GAMES",
    "SOCIAL_NETWORKING_GAMES",
    "ANONYMIZER",
    "COMPUTER_HACKING",
    "COPYRIGHT_INFRINGEMENT",
    "MATURE_HUMOR",
    "OTHER_ILLEGAL_OR_QUESTIONABLE",
    "PROFANITY",
    "QUESTIONABLE",
    "P2P_COMMUNICATION",
    "MILITANCY_HATE_AND_EXTREMISM",
    "ONLINE_AUCTIONS",
    "OTHER_SHOPPING_AND_AUCTIONS",
    "VIOLENCE",
    "WEAPONS_AND_BOMBS",
]

# Webshrinker
# IAB Reference : https://docs.webshrinker.com/v3/iab-website-categories.html#tier-1-and-tier-2-categories

webshrinker_categories_blacklist = [
    "IAB3-1", # Advertising
    "IAB7-39", # Sexuality
    "IAB8-5", #Cocktails / Beer
    "IAB8-18", # Wine
    "IAB9-5", #Board Games / Puzzles
    "IAB9-7", #Card Games
    "IAB9-8", #Chess
    "IAB9-30", #Video & Computer Games
    "IAB9-WS1", # Gambling
    "IAB9-WS2", # Weapons
    "IAB14-1", # Dating / Personals
    "IAB19-WS12", # Hacking / Cracking
    "IAB19-WS2", # VPNs / Proxies & Filter Avoidance'
    "IAB24", #Uncategorized
    "IAB25-1", # Unmoderated UGC / Message Boards
    "IAB25-2", # Extreme Graphic / Explicit Violence
    "IAB25-3", # Adult Content
    "IAB25-4", # Profane Content
    "IAB25-5", # Hate Content
    "IAB25-6", # Under Construction
    "IAB25-7", # Incentivized
    "IAB25-WS3", # Trackers
    "IAB25-WS4", #Cryptomining / Cryptojacking
    "IAB-26", # Illegal Content
    "IAB26-1", # Illegal Content
    "IAB26-2", # Warez
    "IAB26-3", # Spyware / Malware / Malicious
    "IAB26-4", # Copyright Infringement
    "IAB26-WS1", # Illegal Drugs & Paraphernalia
    "IAB26-WS2", # Phishing
]

dnsfilter_category_whitelist = [
'Abortion',
#'Adult Content',
#'Alcohol & Tobacco',
'Blogs & Personal Sites',
'Business',
'Contentious & Misinformation',
'Dating & Personals',
#'Drugs',
'Education & Self Help',
'Entertainment',
'Economy & Finance',
'Food & Recipes',
'Games',
#'Gambling',
'Government',
#'Hacking & Cracking',
'Health',
'Humor',
'Information Technology',
'Jobs & Careers',
'Media Sharing',
'Message Boards & Forums',
'News & Media',
#'P2P & Illegal',
'Real Estate',
'Religion',
'Search Engines & Portals',
'Shopping',
'Social Networking',
'Sports',
'Streaming Media',
'Travel',
#'Terrorism & Hate',
'Vehicles',
'Virtual Reality',
#'Weapons',
'Webmail & Chat'
]

#PLEASE NOTE: the code compare needs to be "lowered", some categories contains spaces.
virustotal_category_whitelist = [
    'military',
    'media sharing',
    'onlineshop',
    'business',
    'business and economy',
    'general business',
    'business/economy',
    ' business/economy'
    'onlineshop',
    'government',
    'travel',
    ' travel',
    'financial',
    'financial data and services',
    'financial services',
    'political organizations',
    'information technology',
    ' information technology',
    'education',
    'web and email marketing',
    'computersandsoftware',
    ' marketing/merchandising',
    ' shopping',
    'online shopping',
    'misc',
    'vehicles',
    'service and philanthropic organizations',
    'bank',
    'reference',
    'shopping',
    'mobile communications',
    'web analytics',
    'reference materials',
    'content delivery',
    'marketing',
    'application and software download',
    'web infrastructure',
    'entertainment',
    'webmail',
    'radio and audio hosting',
    'personal network storage and backup',
    'jobsearch',
    'educational institutions',
    'job search',
    'health and medicines',
    'blogs',
    ' reference',
    'auto',
    'blogs and personal sites',
    'restaurants and dining',
    'food',
    'general email'
    'hosting',
    'email',
    'software-hardware',
    'financial_general',
    'health',
    'hobbies',
    'collaboration - office',
    'hosted business applications',
    ' government/legal',
    'government/legal',
    'real estate',
    'search engines and portals',
    'news',
    'portals',
    'onlinepay',
    'finance',
    'public information',
    'education & reference',
    'computer and internet info',
    'news and media',
    'educational materials',
    'personal network storage',
    'pets',
    'search engines',
    'search engines/portals',
    'portal sites',
    ' search engines/portals',
    ' news',
    'professional and worker organizations',
    'searchengines',
    'sports',
    'social networks',
    'social web - facebook',
    'socialnetworks',
    'onlinephotos',
    'filesharing',
    'file sharing/storage',
    'e-mail',
    'web e mail',
    'general email',
    ' productivity applications',
    'chats',
    'online chat',
    'im',
    'instant messaging',
    'chat/im/sms',
    ' education',
    'internet radio and tv',
    'videos',
    'arts & society & culture',
    'audio',
    ' video/multimedia',
    'web chat',
    'translators',
    'social web - linkedin',
    'business networking'
]

#the code compare the text "lowered"

#DEPRECATED LIST
virustotal_category_blacklist = [
    "celebrity",
    "gossip",
    "adult",
    "adult content",
    "humor",
    "sex",
    "sexually explicit",
    "game",
    "gambling",
    "weapons",
    "dating",
    "hack",
    "crack",
    "avoidance",
    "contest",
    "extrem",
    "explicit",
    "hate",
    "illegal",
    "warez",
    "spyware",
    "spyware and malware",
    "malicious",
    "infringement",
    "drug",
    "phishing",
    "phishing and other frauds",
    "unmoderated",
    "uncategorized",
    "p2p",
    "porn",
    "nudity",
    "anonym",
    "mature",
    "maturecontent",
    "peer to peer",
    "militan",
    "auction",
    "bomb",
    "pornography",
    "adult/mature",
]