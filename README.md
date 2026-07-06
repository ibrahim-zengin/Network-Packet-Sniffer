# # network sniffer

ağ paketlerini yakalamak ve tcp ip yapısını anlamak için yazdığım bir araç. scapy falan kullanmadım tamamen python soketleri ve struct modülüyle ham paketleri çözüyor. paketin kaynak ve hedef ip bilgilerini, ttl değerini ve tcp mi udp mi olduğunu ekrana basıyor.

ağ kartını dinlediği için çalıştırmadan önce terminali yönetici (admin/sudo) olarak açmak gerekiyor yoksa izin hatası verir. python network_sniffer.py ile çalışıyor.
