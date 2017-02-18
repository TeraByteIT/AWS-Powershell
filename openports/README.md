# OpenPorts

This is a PowerShell script that works with Amazon AWS, it will loop through all regions and look for security groups that have '0.0.0.0/0' in the rule and output it to the screen so you can see if things are exposed unnecessarily.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites
PowerShell needs to be installed on Windows, in the later version of Windows, this is done by default.

You need to have PowerShell for AWS installed on a Windows machine in order for this PowerShell script to work.  you can download this from: [https://aws.amazon.com/powershell/](https://aws.amazon.com/powershell/) 

You will also require valid AWS keys (secret / Access) in order to search your AWS account.  Feel free to use a read-only account to ensure nothing malicious is performed.

### Running

Run the PowerShell script with the bare amount of parameters to get the information you want for example:

    AWS_EC2_SG_OpenPorts -AccessKey "ABCDE" -SecretKey "FGHI"

To only search for specific ports that are open to the word, for instance TCP/22 (SSH), you can run the script with the following commands:

    AWS_EC2_SG_OpenPorts -AccessKey "ABCDE" -SecretKey "FGHI" -Port 22

## Built With

* [PowerShell](https://www.microsoft.com/en-gb/download/details.aspx?id=40855) - PowersShell
* [PowerShell for AWS]([https://aws.amazon.com/powershell/) - PowerShell for AWS client


## Authors

* **Marcus Dempsey** - *Initial work* - [TeraByte](https://github.com/TeraByteIT)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the GNU GENERAL PUBLIC License - see the [LICENSE.md](LICENSE.md) file for details