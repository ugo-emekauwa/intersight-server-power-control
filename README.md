<h1 align="center">Automated Server Power Control for Cisco Intersight</h1>

<br>
<p align="center">
  <img alt="Deployment Tools Title Image" title="Deployment Tools" src="./assets/Deployment_Tools_Title_Graphic.png">
</p>  
<br>
<p align="center">
  The Automated Server Power Control Tool for Cisco Intersight automates the power state of multiple UCS servers managed by Intersight. Quickly perform "Power On", "Power Off", "Power Cycle", "Hard Reset", "Shutdown", and "Reboot CIMC" operations on large groups of servers.
</p>
<br>

## Prerequisites
1. Python 3.7 or higher installed, which can be downloaded from [https://www.python.org/downloads/](https://www.python.org/downloads/).
    - If you're installing for the first time on Windows, select the option **"Add Python 3.x to PATH"** during the installation.
2. Install the Cisco Intersight SDK for Python by running the following command:
   ```
   pip install intersight
   ```
   More information on the Cisco Intersight SDK for Python can be found at [https://github.com/ciscodevnet/intersight-python](https://github.com/ciscodevnet/intersight-python).
3. [_Optional_] If you already have the Cisco Intersight SDK for Python installed, you may need to upgrade. An upgrade can be performed by running the following command:
   ```
   pip install intersight --upgrade --user
   ```
4. Clone or download the **Automated Server Power Control for Cisco Intersight** repository by using the ![GitHub Code Button](./assets/GitHub_Code_Button.png "GitHub Code Button") link on the main repository web page or by running the following command from the target directory if Git is locally installed:
    ```
    git clone https://github.com/ugo-emekauwa/intersight-server-power-control
    ```
   If you are downloading the repository file as a zipped file, unzip the file once the download has completed.
5. Generate a version 3 or version 2 API key from your Intersight account.

    **(a).** Log into your Intersight account, click the Service Selector and select **System**.
    
      ![Figure 1 - Go to Settings](./assets/Figure_1_Go_to_Settings.png "Figure 1 - Go to Settings")
      
    **(b).** Under the API section in the work pane, click **API Keys**.
    
      ![Figure 2 - Go to API Keys](./assets/Figure_2_Go_to_API_Keys.png "Figure 2 - Go to API Keys")
      
    **(c).** In the API Keys section in the work pane, click the **Generate API Key** button.
    
      ![Figure 3 - Click the Generate API Key button](./assets/Figure_3_Click_the_Generate_API_Key_button.png "Figure 3 - Click the Generate API Key button")
      
    **(d).** In the Generate API Key window, enter a description or name for your API key.
    
      ![Figure 4 - Enter an API key description](./assets/Figure_4_Enter_an_API_key_description.png "Figure 4 - Enter an API key description")
      
    **(e).** In the Generate API Key window, under API Key Purpose, select a version 3 or version 2 API key.
    
      ![Figure 5 - Verify version 2 API key selection](./assets/Figure_5_Verify_version_2_API_key_selection.png "Figure 5 - Verify version 2 API key selection")
      
    **(f).** In the Generate API Key window, click the **Generate** button.
    
      ![Figure 6 - Click the Generate button](./assets/Figure_6_Click_the_Generate_button.png "Figure 6 - Click the Generate button")
      
    **(g).** In the Generate API Key window, a new API key will be generated. Copy the API Key ID and download the Secret Key to a secure location.
    
      ![Figure 7 - Copy and save the API key data](./assets/Figure_7_Copy_and_save_the_API_key_data.png "Figure 7 - Copy and save the API key data")

## How to Use
1. Please ensure that the above [**Prerequisites**](https://github.com/ugo-emekauwa/intersight-server-power-control#prerequisites) have been met.
2. Within the unzipped **Automated Server Power Control for Cisco Intersight** repository, navigate to the intersight_server_power_control.py file.
3. Edit the intersight_server_power_control.py file to set the **`key_id`** variable using the following instructions:

    **(a).** Open the intersight_server_power_control.py file in an IDLE or text editor of choice.
    
    **(b).** Find the comment **`# MODULE REQUIREMENT 1 #`**.
     
      ![Figure 9 - MODULE REQUIREMENT 1 location](./assets/Figure_9_MODULE_REQUIREMENT_1_location.png "Figure 9 - MODULE REQUIREMENT 1 location")
      
    **(c).** Underneath, you will find the variable **`key_id`**. The variable is currently empty.
    
      ![Figure 10 - key_id variable location](./assets/Figure_10_key_id_variable_location.png "Figure 10 - key_id variable location")
      
    **(d).** Fill in between the quotes of the **`key_id`** variable value with the ID of your API key. For example:
      ```py
      key_id = "5c89885075646127773ec143/5c82fc477577712d3088eb2f/5c8987b17577712d302eaaff"
      ```
4. Edit the intersight_server_power_control.py file to set the **`key`** variable using the following instructions:

    **(a).** Open the intersight_server_power_control.py file in an IDLE or text editor of choice.
    
    **(b).** Find the comment **`# MODULE REQUIREMENT 2 #`**.
    
      ![Figure 11 - MODULE REQUIREMENT 2 location](./assets/Figure_11_MODULE_REQUIREMENT_2_location.png "Figure 11 - MODULE REQUIREMENT 2 location")
      
    **(c).** Underneath, you will find the variable **`key`**. The variable is currently empty.
    
      ![Figure 12 - key variable location](./assets/Figure_12_key_variable_location.png "Figure 12 - key variable location")
      
    **(d).** Fill in between the quotes of the **`key`** variable value with your system's file path to the SecretKey.txt file for your API key. For example:
      ```py
      key = "C:\\Keys\\Key1\\SecretKey.txt"
      ```
5. Edit the intersight_server_power_control.py file to set all the configuration variable values using the following instructions:

    **(a).** Open the intersight_server_power_control.py file in an IDLE or text editor of choice.

    **(b).** Find the comment **`# MODULE REQUIREMENT 3 #`**.
    
      ![Figure 13 - MODULE REQUIREMENT 3 location](./assets/Figure_13_MODULE_REQUIREMENT_3_location.png "Figure 13 - MODULE REQUIREMENT 3 location")
      
    **(c).** Underneath, you will find the instructions to edit the configuration variable values to match your environment. Each variable has a sample value for ease of use. The variable values to edit begin under the comment **`####### Start Configuration Settings - Provide values for the variables listed below. #######`**.
      
      ![Figure 14 - Start Configuration Settings location](./assets/Figure_14_Start_Configuration_Settings_location.png "Figure 14 - Start Configuration Settings location")
   
    Completion of editing the configuration variable values is marked by the comment **`####### Finish Configuration Settings - The required value entries are complete. #######`**.
      
      ![Figure 15 - Finish Configuration Settings location](./assets/Figure_15_Finish_Configuration_Settings_location.png "Figure 15 - Finish Configuration Settings location")
6. Save the changes you have made to the intersight_server_power_control.py file.
7. Run the intersight_server_power_control.py file.

## Demonstrations and Learning Labs
The Automated Server Power Control Tool for Cisco Intersight is used in the following demonstrations and labs on Cisco dCloud:

- [Run Gen AI and LLMs on Cisco UCS X-Series with NVIDIA GPUs](https://dcloud2.cisco.com/demo/run-gen-ai-and-llms-on-cisco-ucs-x-series)
<br><br>

![Cisco UCS X-Series Lab Topology](./assets/Cisco_UCS_X-Series_Lab_Topology_2.png "Cisco UCS X-Series Lab Topology")
<br><br>

dCloud is available at [https://dcloud.cisco.com](https://dcloud.cisco.com), where Cisco product demonstrations and labs can be found in the Catalog.

## Related Tools
Here are similar tools to help administer and manage Cisco UCS and Intersight environments.
- [Cisco IMM Automation Tools](https://github.com/ugo-emekauwa/cisco-imm-automation-tools)
- [Automated OS Install Tool for Cisco Intersight](https://github.com/ugo-emekauwa/intersight-os-installer)
- [UCS CIMC Certificate Renewal Tool](https://github.com/ugo-emekauwa/ucs_cimc_csr_tool)

## Author
Ugo Emekauwa

## Contact Information
uemekauw@cisco.com or uemekauwa@gmail.com
