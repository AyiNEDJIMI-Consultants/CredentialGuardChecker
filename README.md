# 🚀 Credential Guard Checker


**Ayi NEDJIMI Consultants - WinToolsSuite**

## 📋 Description

Outil de vérification complète des états VBS (Virtualization-Based Security), Credential Guard, HVCI et attestation TPM pour la sécurité Windows.


## ✨ Fonctionnalités

- **Vérification VBS**: Query WMI Win32_DeviceGuard pour VirtualizationBasedSecurityStatus
- **Credential Guard**: Détection via SecurityServicesRunning (bit 1)
- **HVCI**: Vérification Hypervisor-protected Code Integrity (bit 2)
- **TPM**: Détection présence via Tbsi_GetDeviceInfo
- **Prérequis**: Test Secure Boot, DEP, Architecture, Virtualisation
- **Configuration registre**: Lecture HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
- **Export CSV UTF-8 BOM**: Sauvegarde du rapport de vérification


## 🔌 APIs Utilisées

- `wbemuuid.lib`: WMI pour Win32_DeviceGuard (états VBS/CG/HVCI)
- `tbs.lib`: TPM Base Services (Tbsi_Context_Create, Tbsi_GetDeviceInfo)
- `advapi32.lib`: Accès registre et GetFirmwareEnvironmentVariable
- `comctl32.lib`: ListView, StatusBar


## Compilation

```batch
go.bat
```

Ou manuellement:
```batch
cl.exe /EHsc /std:c++17 CredentialGuardChecker.cpp wbemuuid.lib comctl32.lib tbs.lib advapi32.lib ole32.lib oleaut32.lib user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS
```


## 🚀 Utilisation

1. **Vérifier VBS/CG**: Interroge WMI pour obtenir les états de sécurité
2. **Tester prérequis**: Vérifie Secure Boot, TPM, DEP, configuration registre
3. **Exporter rapport**: Sauvegarde en CSV UTF-8


## Interprétation des États

- **0**: Désactivé
- **1**: Activé mais pas en cours d'exécution
- **2**: Activé et en cours d'exécution (optimal)

### SecurityServicesRunning Bitmask

- **Bit 1**: Credential Guard
- **Bit 2**: HVCI (Hypervisor-protected Code Integrity)


## 📌 Prérequis Système

- Windows 10 Enterprise/Education ou Windows Server 2016+
- UEFI avec Secure Boot
- TPM 2.0
- Virtualisation matérielle (VT-x/AMD-V)
- DEP activé
- IOMMU support


## Logging

Logs sauvegardés dans: `%TEMP%\CredentialGuardChecker.log`


## Structure

- **WMI COM**: Interrogation Win32_DeviceGuard via IWbemServices
- **TPM TBS**: Détection TPM via TPM Base Services
- **UI Française**: Interface complète en français


## 💬 Notes

- Credential Guard protège les identifiants contre vol (Pass-the-Hash, etc.)
- HVCI garantit l'intégrité du code en mode noyau via hyperviseur
- VBS requiert support matériel et configuration appropriée

- --

**WinToolsSuite** - Sécurité et Administration Windows
Ayi NEDJIMI Consultants © 2025


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>