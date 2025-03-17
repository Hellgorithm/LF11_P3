# LF11_P3 - Active Directory Domain Automation

This repository contains scripts for automating the configuration and management of Microsoft Active Directory Domain Services (ADDS) environments.

## Main Features

- Automated domain environment setup
- Organizational Unit (OU) creation
- User management from configuration files
- Network share setup with proper permissions
- DHCP configuration
- Print settings management

## Repository Contents

- **DomainConfiguration.ps1**: Main script for domain configuration
- **domainConfig.json**: Example Config file

## Requirements

- Windows Server 2016 or newer (tested on Windows Server 2022, build 20348.3328)
- PowerShell 5.1 or later
- Active Directory module
- Administrative privileges

## Configuration

The script uses JSON configuration files located in the configs subfolder. The main configuration file is `domainConfig.json` which contains:

- User definitions
- Group assignments
- Organizational Unit structures
- Network share configurations
- DHCP settings

## Usage

1. Create or modify the configuration files in the configs folder
2. Run the main script:

```powershell
.\DomainConfiguration.ps1
```

You will be prompted for a starting password for new users during execution.
*This Password is universal for all non-Administrative Users and should be changed as soon as possible.*

## Structure

The DomainConfiguration script uses a structured approach:

- **Global Variables**: Defines paths, domains, and collections
- **Classes**: Defines two classes for readability and ease of import
- **Helper Functions**: Handles logging, config reading, and domain operations
- **Main Section**: Orchestrates the configuration process

## Logs

The script generates logs at `DomainConfig.log` in the script directory, with automatic pruning when the log exceeds 2MB.

## Links

- GitHub Repository: [https://github.com/Hellgorithm/LF11_P3](https://github.com/Hellgorithm/LF11_P3)

## Author

- HGR

---

*Last Updated: 10.01.2025*