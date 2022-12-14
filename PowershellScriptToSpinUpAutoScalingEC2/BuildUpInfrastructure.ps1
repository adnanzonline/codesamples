<# The script fill perform following Steps
------------------------------------------
.SYNOPSIS
	This script will build the Infrastructure of the application and deploy the application on Amazon AWS, it will perform following steps:
	
.DESCRIPTION 
	 1. Tear down the complete infrastructure of the application first, IF ALREADY EXIST.
	 2. Create Load balancer
	 3. Create Launch configurations
	 4. Create Instances and instance's Tags
	 5. Create Scale up and down policies
	 6. Create Metric alarms
	 7. Add Instances to the load balancer
	 8. Create Route53 domain name
	 
.NOTES
	File Name 			: BuildUpInfrastructure.ps1
	Author	            : Adnan Zafar
	Prerequisite		: Powershell V2, Windows 2008+
	
.PARAMETERS
	#$pProjectKey						==> Project key	e.g CORE
	#$pKey								==>	AWS key normally we use "AWSKEY"
	#$pKeySecret						==> AWS secret key normally we use "AWSSECRET"
	#$pKeyPairName						==> AWS key pair name normally we use "Automation"
	#$pETag								==> Environment tag, can be "s" or "p"
	#$pBuildNumber						==> Bamboo build number, It will get from bamboo latest build number
	#$pWinServiceFlag					==> Can be true or false (If there is/are WinService(s) in project, make it true, else make it false)
 
  -Web parameters:	
	# VARIABLES for load balancers
	#-----------------------------
	#$pWebLoadBalancerInstancePort		==> Port number for instance in web load balancer e.g 80 or any other
	#$pWebLoadBalancerPort				==> Can be 80 or 443, if SSL Certificate Id is created for project, then make it 443, otherwise 80
	#$pWebLoadBalancerProtocol			==> Can be "HTTPS" or "HTTP", if SSL Certificate Id is created for project, then make it HTTPS, otherwise HTTP
	#$pWebLoadBalancerInstanceProtocol	==> Protocol for instance in web load balancer, e.g HTTP
	#$pWebLoadBalancerSSLCertificateId	==> SSL Certificate id for project, which create upone client request, e.g CORESSL
	#$pWebLoadBalancerRequestScheme		==> Request scheme for web load balancer e.g internet-facing
	
	# VARIABLES for launch configuration
	#-----------------------------------
	#$pAMIid							==> AWS AMI ID normally we use "ami-ea43f79d"
	#$pInstanceType						==> Type of the instances to be lanuched ..t1.micro, medium etc
	#$pSecurityGroup					==> Security group. AWS-Automation, This general security group created for automation.
	
	# VARIABL for instance(s) zone(S)
	#--------------------------------
	#$pNumberOfZones					==> Can be 1 or 2 or 3, Define how many zones you want to create. So Zone-A, Zone-B... etc will be created
	
	# VARIABLES for ScalePolicies
	#----------------------------
	#$pWebScaleUpPolicyRequestCooldown,	#// 300
	#$pWebScaleUpPolicyRequestScalingAdjustment,	#// 1
	#$pWebScaleUpPolicyRequestAdjustmentType,	#// "ChangeInCapacity"

	#$pWebScaleDownPolicyRequestCooldown,	#// 300
	#$pWebScaleDownPolicyRequestScalingAdjustment,	#// -1
	#$pWebScaleDownPolicyRequestAdjustmentType,	#// "ChangeInCapacity"
	
	# VARIABLES for scale alarms
	#$pScaleUpAlarmDescription,	#// "Scale up at 80% load"
	#$pScaleUpMetricName,	#// "CPUUtilization"
	#$pScaleUpPeriod,	#// 60
	#$pScaleUpThreshold, 	#// 80
	#$pScaleUpComparisonOperator,	#// "GreaterThanThreshold"
	#$pScaleUpEvaluationPeriods,	#// 3
	#$pScaleUpUnit,	#// "Percent"

	#$pScaleDownAlarmDescription,	#// "Scale down at 20% load"
	#$pScaleDownMetricName,	#// "CPUUtilization"
	#$pScaleDownPeriod,	#// 60
	#$pScaleDownThreshold,	#// 20
	#$pScaleDownComparisonOperator,	#// "LessThanThreshold"
	#$pScaleDownEvaluationPeriods,	#// 3
	#$pScaleDownUnit,	#// "Percent"

	# VARIABLES for ScaleMatricAlarms
	#$pWebAlarmScaleUpNamespace,	#// "AWS/EC2"
	#$pWebAlarmScaleUpStatistic,	#// "Average"

	#$pWebAlarmScaleDownNamespace,	#// "AWS/EC2"
	#$pWebAlarmScaleDownStatistic,	#// "Average"
	
	# VARIABLES for Route53DomainNames	
	#$pHostedZoneId,	#// Z1Q6KU2TGQHXS7
	#$pRouteDomainName,	#// core.s.aws.togethersupport.co.uk
	#$pRoute53RRSetType,	#// 'CNAME'
	#$pRoute53RRSetTTL	#// 300
	
  -App parameters:
	# VARIABLES for load balancers
	#-----------------------------	
	#$pAppLoadBalancerInstancePort		==> Port number for instance in app load balancer e.g 80 or any other
	#$pAppLoadBalancerPort				==> Port number for app load balancer e.g 80 or any other
	#$pAppLoadBalancerProtocol			==> Protocol for app load balancer, e.g HTTP
	#$pAppLoadBalancerInstanceProtocol	==> Protocol for instance in app load balancer, e.g HTTP
	#$pAppLoadBalancerRequestScheme		==> Request scheme for app load balancer e.g internet-facing
	
	# VARIABLES for ScalePolicies
	#----------------------------
	#$pAppScaleUpPolicyRequestCooldown,	#// 300
	#$pAppScaleUpPolicyRequestScalingAdjustment,	#// 1
	#$pAppScaleUpPolicyRequestAdjustmentType,	#// "ChangeInCapacity"

	#$pAppScaleDownPolicyRequestCooldown,	#// 300
	#$pAppScaleDownPolicyRequestScalingAdjustment,	#// -1
	#$pAppScaleDownPolicyRequestAdjustmentType,	#// "ChangeInCapacity"
	
	# VARIABLES for ScaleMatricAlarms
	#$pAppAlarmScaleUpNamespace,	#// "AWS/EC2"
	#$pAppAlarmScaleUpStatistic,	#// "Average"

	#$pAppAlarmScaleDownNamespace,	#// "AWS/EC2"
	#$pAppAlarmScaleDownStatistic,	#// "Average"
#>

 param 
 (
	$pProjectKey,
	$pKey,
	$pKeySecret,
	$pKeyPairName,
	$pETag,
	$pBuildNumber,	
	$pWinServiceFlag,
    $pInstanceIDofScheduler,
	
# Web variables
#--------------
	# VARIABLES for load balancers
	$pWebLoadBalancerInstancePort,
	$pWebLoadBalancerPort,	
	$pWebLoadBalancerProtocol,	
	$pWebLoadBalancerInstanceProtocol, 
	$pWebLoadBalancerSSLCertificateId,	
	$pWebLoadBalancerRequestScheme,
    $pWebLoadBalancerHTTPPort,
    $pWebLoadBalancerHTTPProtocol,
	
	# VARIABLES for launch configuration
	$pAMIid,	
	$pInstanceType,	
	$pSecurityGroup,	
	
	# VARIABL for instance(s) zone(S)
	$pNumberOfZones,	
	
	# VARIABLES for ScalePolicies
	$pWebScaleUpPolicyRequestCooldown,	
	$pWebScaleUpPolicyRequestScalingAdjustment,
	$pWebScaleUpPolicyRequestAdjustmentType,	

	$pWebScaleDownPolicyRequestCooldown,	
	$pWebScaleDownPolicyRequestScalingAdjustment,	
	$pWebScaleDownPolicyRequestAdjustmentType,	
	
	# VARIABLES for scale alarms
	$pScaleUpAlarmDescription,	
	$pScaleUpMetricName,	
	$pScaleUpPeriod,	
	$pScaleUpThreshold, 	
	$pScaleUpComparisonOperator,	
	$pScaleUpEvaluationPeriods,	
	$pScaleUpUnit,	

	$pScaleDownAlarmDescription,	
	$pScaleDownMetricName,	
	$pScaleDownPeriod,	
	$pScaleDownThreshold,	
	$pScaleDownComparisonOperator,	
	$pScaleDownEvaluationPeriods,	
	$pScaleDownUnit,	

	# VARIABLES for ScaleMatricAlarms
	$pWebAlarmScaleUpNamespace,
	$pWebAlarmScaleUpStatistic,	

	$pWebAlarmScaleDownNamespace,	
	$pWebAlarmScaleDownStatistic,
	
	# VARIABLES for Route53DomainNames	
	$pHostedZoneId,	
	$pRouteDomainName,	
	$pRoute53RRSetType,	
	$pRoute53RRSetTTL,	
	
# App variables
#--------------
	# VARIABLES for load balancers
	$pAppLoadBalancerInstancePort,
	$pAppLoadBalancerPort,	
	$pAppLoadBalancerProtocol,	
	$pAppLoadBalancerInstanceProtocol,	
	$pAppLoadBalancerRequestScheme,	

	# VARIABLES for ScalePolicies
	$pAppScaleUpPolicyRequestCooldown,	
	$pAppScaleUpPolicyRequestScalingAdjustment,	
	$pAppScaleUpPolicyRequestAdjustmentType,	

	$pAppScaleDownPolicyRequestCooldown,	
	$pAppScaleDownPolicyRequestScalingAdjustment,	
	$pAppScaleDownPolicyRequestAdjustmentType,	
	
	# VARIABLES for ScaleMatricAlarms
	$pAppAlarmScaleUpNamespace,	
	$pAppAlarmScaleUpStatistic,	

	$pAppAlarmScaleDownNamespace,	
	$pAppAlarmScaleDownStatistic	
)


cls
echo "Starting Process"
import-module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"
Add-Type -Path "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSSDK.dll"#



# Initial Settings
$ProjectKey = $pProjectKey.ToUpper()
$Key = $pKey
$KeySecret = $pKeySecret
$KeyPairName = $pKeyPairName
$ETag = $pETag.ToUpper()
$BuildNumber = $pBuildNumber
$WinServiceFlag = $pWinServiceFlag.ToLower()
$instanceIDofScheduler = $pInstanceIDofScheduler


# VARIABLES definitions for load balancers
$WebLoadBalancerInstancePort = $pWebLoadBalancerInstancePort
$WebLoadBalancerPort = $pWebLoadBalancerPort
$WebLoadBalancerProtocol = $pWebLoadBalancerProtocol	
$WebLoadBalancerInstanceProtocol = $pWebLoadBalancerInstanceProtocol 
$WebLoadBalancerSSLCertificateId = $pWebLoadBalancerSSLCertificateId	
$WebLoadBalancerRequestScheme = $pWebLoadBalancerRequestScheme	

$WebLoadBalancerHTTPPort = $pWebLoadBalancerHTTPPort #For LB HTTP Listener
$WebLoadBalancerHTTPProtocol = $pWebLoadBalancerHTTPProtocol #For LB HTTP Listener

$AppLoadBalancerInstancePort = $pAppLoadBalancerInstancePort	
$AppLoadBalancerPort = $pAppLoadBalancerPort	
$AppLoadBalancerProtocol = $pAppLoadBalancerProtocol	
$AppLoadBalancerInstanceProtocol = $pAppLoadBalancerInstanceProtocol	
$AppLoadBalancerRequestScheme = $pAppLoadBalancerRequestScheme	

$LBDNSNameWeb = "" # this will get populated upon creation of load balancer
$LBDNSNameApp = "" # this will get populated upon creation of load balancer


# VARIABLES definitions for launch configuration
$AMIid = $pAMIid
$InstanceType = $pInstanceType	
$SecurityGroupType = $pSecurityGroup

$SecurityGroup = New-Object “System.Collections.Generic.List[String]”
$SecurityGroup.Add($SecurityGroupType)

$LaunchConfigurationNameWeb = "$ProjectKey-$ETag-WEB"
$LaunchConfigurationNameWinService = "$ProjectKey-$ETag-APP"
$AutoScalingGroupForWeb = "$ProjectKey-$ETag-WEB"
$AutoScalingGroupForApp = "$ProjectKey-$ETag-APP"
	
	
# VARIABL definitions for instance(s) zone(S)
	# All instance settings are there in Instance section


# VARIABL definitions for ScalePolicies
$ScaleUpPolicyForWeb= "$ProjectKey-$ETag-UP-WEB"
$WebScaleUpPolicyRequestCooldown = $pWebScaleUpPolicyRequestCooldown	
$WebScaleUpPolicyRequestScalingAdjustment = $pWebScaleUpPolicyRequestScalingAdjustment	
$WebScaleUpPolicyRequestAdjustmentType = $pWebScaleUpPolicyRequestAdjustmentType	

$ScaleDownPolicyForWeb = "$ProjectKey-$ETag-DOWN-WEB"
$WebScaleDownPolicyRequestCooldown = $pWebScaleDownPolicyRequestCooldown	
$WebScaleDownPolicyRequestScalingAdjustment = $pWebScaleDownPolicyRequestScalingAdjustment	
$WebScaleDownPolicyRequestAdjustmentType = $pWebScaleDownPolicyRequestAdjustmentType	

$ScaleUpPolicyForApp = "$ProjectKey-$ETag-UP-APP"
$AppScaleUpPolicyRequestCooldown = $pAppScaleUpPolicyRequestCooldown	
$AppScaleUpPolicyRequestScalingAdjustment = $pAppScaleUpPolicyRequestScalingAdjustment	
$AppScaleUpPolicyRequestAdjustmentType = $pAppScaleUpPolicyRequestAdjustmentType	

$ScaleDownPolicyForApp = "$ProjectKey-$ETag-DOWN-APP"
$AppScaleDownPolicyRequestCooldown = $pAppScaleDownPolicyRequestCooldown	
$AppScaleDownPolicyRequestScalingAdjustment = $pAppScaleDownPolicyRequestScalingAdjustment	
$AppScaleDownPolicyRequestAdjustmentType = $pAppScaleDownPolicyRequestAdjustmentType	


# VARIABLES definitions for scale alarms
$ScaleUpAlarmNameForWeb = "$ProjectKey-$ETag-UP-WEB"
$ScaleUpAlarmDescription = $pScaleUpAlarmDescription	
$ScaleUpMetricName = $pScaleUpMetricName	
$ScaleUpPeriod = $pScaleUpPeriod	
$ScaleUpThreshold = $pScaleUpThreshold 	
$ScaleUpComparisonOperator = $pScaleUpComparisonOperator	
$ScaleUpEvaluationPeriods = $pScaleUpEvaluationPeriods	
$ScaleUpUnit = $pScaleUpUnit	

$ScaleDownAlarmNameForWeb = "$ProjectKey-$ETag-DOWN-WEB"
$ScaleDownAlarmDescription = $pScaleDownAlarmDescription	
$ScaleDownMetricName = $pScaleDownMetricName	
$ScaleDownPeriod = $pScaleDownPeriod	
$ScaleDownThreshold = $pScaleDownThreshold	
$ScaleDownComparisonOperator = $pScaleDownComparisonOperator	
$ScaleDownEvaluationPeriods = $pScaleDownEvaluationPeriods	
$ScaleDownUnit = $pScaleDownUnit	

$ScaleUpAlarmNameForApp = "$ProjectKey-$ETag-UP-APP"
$ScaleDownAlarmNameForApp = "$ProjectKey-$ETag-DOWN-APP"


# VARIABLES definitions for ScaleMatricAlarms
$WebAlarmScaleUpNamespace = $pWebAlarmScaleUpNamespace	
$WebAlarmScaleUpStatistic = $pWebAlarmScaleUpStatistic	

$WebAlarmScaleDownNamespace = $pWebAlarmScaleDownNamespace	
$WebAlarmScaleDownStatistic = $pWebAlarmScaleDownStatistic	

$AppAlarmScaleUpNamespace = $pAppAlarmScaleUpNamespace	
$AppAlarmScaleUpStatistic = $pAppAlarmScaleUpStatistic	

$AppAlarmScaleDownNamespace = $pAppAlarmScaleDownNamespace	
$AppAlarmScaleDownStatistic = $pAppAlarmScaleDownStatistic	


# VARIABLES definitions for Route53DomainNames	
$HostedZoneId = $pHostedZoneId
$Route53DomainName = $pRouteDomainName
$Route53RRSetType = $pRoute53RRSetType	
$Route53RRSetTTL = $pRoute53RRSetTTL	



#File names of ExecutionScriptForWebProjects and ExecutioinScriptForWinServices
$UserDataFileName = ".\ExecuteWebProjectsScript.ps1"
$UserDataFileNameWinService = ""
if($WinServiceFlag -eq 'true')
{
	$UserDataFileNameWinService = ".\ExecuteWinServicesScript.ps1"
}


# Policy ARN's variables will be populated down later
$ScaleUpPolicyARNWeb = ""
$ScaleDownPolicyARNWeb = ""

$ScaleUpPolicyARNApp = ""
$ScaleDownPolicyARNApp = ""

$LBWeb = "$ProjectKey-$ETag-WEB"
$LBApp = "$ProjectKey-$ETag-APP"

$LBHostedWebID = ""
$LBHostedAppID = ""



#########################################################################################
$Path = split-path -parent $MyInvocation.MyCommand.Definition
$ParentPath = split-path -Parent $Path
Set-Location $Path
echo "Parent Path = $ParentPath"
echo "Full Path = $Path"

$Region = [Amazon.RegionEndpoint]::EUWest1

$EC2Config = New-Object Amazon.EC2.AmazonEC2Config
$EC2Config.RegionEndpoint = $Region

$ELBConfig = New-Object Amazon.ElasticLoadBalancing.AmazonElasticLoadBalancingConfig 
$ELBConfig.RegionEndpoint = $Region

$ASConfig = New-Object Amazon.AutoScaling.AmazonAutoScalingConfig
$ASConfig.RegionEndpoint = $Region

$CWConfig = New-Object Amazon.CloudWatch.AmazonCloudWatchConfig
$CWConfig.RegionEndpoint = $Region

$Route53Config = New-object Amazon.Route53.AmazonRoute53Config 
$Route53Config.RegionEndpoint = $Region

$EC2Client = New-Object Amazon.EC2.AmazonEC2Client($Key,$KeySecret,$EC2Config) 
$ELBClient = New-Object Amazon.ElasticLoadBalancing.AmazonElasticLoadBalancingClient($Key,$KeySecret,$ELBConfig)
$ASClient = New-Object Amazon.AutoScaling.AmazonAutoScalingClient($Key,$KeySecret,$ASConfig)
$CWClient = New-Object Amazon.CloudWatch.AmazonCloudWatchClient($Key,$KeySecret,$CWConfig)
$Route53Client = New-object Amazon.Route53.AmazonRoute53Client($Key,$KeySecret,$Route53Config)


#region INSTANCES SETTINGS

$TagValueApp = $ProjectKey + "-" + $ETag + "-APP-" + $BuildNumber
$InstanceIdApp = ""

[System.Collections.ArrayList]$TagValuesWeb = @()
[System.Collections.ArrayList]$InstanceIdsWeb = @()
$Zones = New-Object “System.Collections.Generic.List[String]”
$NumberOfZones = $pNumberOfZones

$Alphabets = 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'

for($i=0; $i -lt $NumberOfZones; $i++)
{
    $TagValuesWeb.Add($ProjectKey + "-" + $ETag + "-WEB-" + $Alphabets[$i] + "-" + $BuildNumber)
    $Zones.Add("eu-west-" + 1 + $Alphabets[$i].ToLower())
}

	$client = [Amazon.AWSClientFactory]::CreateAmazonEC2Client($Key,$KeySecret,$EC2Config)
	
	# Run Request for web server
	# get script to run on start up. Encode it with Base64
	$userDataContent = Get-Content $UserDataFileName -Raw
	$bytes = [System.Text.Encoding]::Utf8.GetBytes($userDataContent)
	$userDataContent = [Convert]::ToBase64String($bytes)
	
	$runRequest = new-object Amazon.EC2.Model.RunInstancesRequest
	
	$runRequest.ImageId = $AMIid
	$runRequest.KeyName = $KeyPairName
	$runRequest.MaxCount = "1"
	$runRequest.MinCount = "1"
	$runRequest.InstanceType = $InstanceType
	$runRequest.SecurityGroupIds = $SecurityGroup
	$runRequest.UserData = $userDataContent
	
	
	# Run Request for App Server
	
	# get script to run on start up. Encode it with Base64
	$userDataContentWinService = ""
	$runRequestWinService = ""
	
if($WinServiceFlag -eq 'true')
{
	$userDataContentWinService = Get-Content $UserDataFileNameWinService -Raw
	$bytesWinService = [System.Text.Encoding]::Utf8.GetBytes($userDataContentWinService)
	$userDataContentWinService = [Convert]::ToBase64String($bytesWinService)
	
	$runRequestWinService = new-object Amazon.EC2.Model.RunInstancesRequest
	
	$runRequestWinService.ImageId = $AMIid
	$runRequestWinService.KeyName = $KeyPairName
	$runRequestWinService.MaxCount = "1"
	$runRequestWinService.MinCount = "1"
	$runRequestWinService.InstanceType = $InstanceType
	$runRequestWinService.SecurityGroupIds = $SecurityGroup
	$runRequestWinService.UserData = $userDataContentWinService
}

#endregion instance settings END ______



#_______________________________________________________#
#														#
# 	Methods for TearDown the complete Infrastructure	#
#														#
#_______________________________________________________#

# Function to delete Instances
function TerminateInstances
{	
    $ListLB = New-Object “System.Collections.Generic.List[String]”
	$Response = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersResponse
    $Response = $ELBClient.DescribeLoadBalancers()
	if($Response.DescribeLoadBalancersResult.Count -gt 0)
	{
		foreach($LBDescription in $Response.DescribeLoadBalancersResult.LoadBalancerDescriptions)
   		{
			if($LBDescription.LoadBalancerName -eq $LBWeb)
			{
				$ListLB.Add($LBWeb)
			}
			if($LBDescription.LoadBalancerName -eq $LBApp)
			{
				$ListLB.Add($LBApp)
			}
	    }		
		if($ListLB.Count -gt 0)
		{
			$DescribeRequest = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersRequest
			$DescribeRequest.LoadBalancerNames = $ListLB
			
			$DescribeResponse = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersResponse
			try
			{
				$DescribeResponse = $ELBClient.DescribeLoadBalancers($DescribeRequest)
			}
			catch
			{
				echo "Error"
				echo $_.Exception.ToString()
			}			
			if($DescribeResponse.DescribeLoadBalancersResult.Count -gt 0)
			{
				foreach($LBFromServer in $DescribeResponse.DescribeLoadBalancersResult.LoadBalancerDescriptions)
				{
					$ListInstancesString = New-Object “System.Collections.Generic.List[String]”
					$ListInstancesFromServer = $LBFromServer.Instances
					
					$ListInstancesOfTypeInstanceToUnregister = New-Object System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Instance]
					
					if($ListInstancesFromServer.Count -ne 0)
					{
						foreach($InstanceItem in $ListInstancesFromServer)
						{
							$ListInstancesString.Add($InstanceItem.InstanceId) # String List to Terminate
							$instance = New-Object Amazon.ElasticLoadBalancing.Model.Instance
							$instance.InstanceId = $InstanceItem.InstanceId
							$ListInstancesOfTypeInstanceToUnregister.add($instance) # Instance Type List to Unregister from Load Balancer
						}
						$DeregisterInstancesRequest = New-Object Amazon.ElasticLoadBalancing.Model.DeregisterInstancesFromLoadBalancerRequest
						$DeregisterInstancesRequest.Instances = $ListInstancesOfTypeInstanceToUnregister
						$DeregisterInstancesRequest.LoadBalancerName = $LBFromServer.LoadBalancerName
						try 
						{
							echo "Deregistring Instances from Load Balancers...."
							$ELBClient.DeregisterInstancesFromLoadBalancer($DeregisterInstancesRequest)
							echo "Deregistration Successfully Done"
						}
						catch 
						{
							echo "Error"
							echo $_.Exception.ToString()
						}
						foreach($Ins in $ListInstancesString)
                        {
                            # instanceId for EC2-Scheduler "i-3a638b96"
						    if($Ins -ne $instanceIDofScheduler)
						    {
							    $TerminateResponse = New-Object Amazon.EC2.Model.TerminateInstancesResponse
							    $TerminateRequest = New-Object Amazon.EC2.Model.TerminateInstancesRequest
							    $TerminateRequest.InstanceIds = $Ins
							    try 
							    {
								    echo "Terminating..."
								    $TerminateResponse = $EC2Client.TerminateInstances($TerminateRequest)
								    echo "Instances Terminated Successfully"
							    }
							    catch 
							    {
								    echo "Error"
								    echo $_.Exception.ToString()
							    }
						    }
                        }
					}
				}
			}
		}
        # This section attaches the temporary instance 'MICROINSTANCE-STAGING' (or LIVE or SANDBOX or SiteUnderMaintenance), to the LoadBalancer.
         # The instance will have a simple page on IIS. The page will show a maintenance message for the users, in order to cover the downtime of site while it is being under deployment process.
         #First get the ID from file in which it is stored by previous script (MicroInstance.CreateAndStart.ps1)
         $fileName = "MicroInstanceID.txt"
         if(Test-Path ${bamboo.build.working.directory}\$fileName)
         {
             $instanceIDofSiteUnderMaintenace = Get-Content ${bamboo.build.working.directory}\$fileName
         }

         #Code to Register MICROINSTANCE-STAGING Instance to Loadbalancers
         $RegisterInstancesRequest = New-Object Amazon.ElasticLoadBalancing.Model.RegisterInstancesWithLoadBalancerRequest
         $Instances = New-Object System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Instance]
         $Instance = New-Object Amazon.ElasticLoadBalancing.Model.Instance

         $Instance.InstanceId = $instanceIDofSiteUnderMaintenace
         $Instances.Add($Instance) #add instance to its list
	     $RegisterInstancesRequest.Instances = $Instances
         $RegisterInstancesRequest.LoadBalancerName = $LBWeb
         
	     try 
	     {
             echo "Adding micro instance to load balancer"
	         $ELBClient.RegisterInstancesWithLoadBalancer($RegisterInstancesRequest)
	         echo "The instance 'MICROINSTANCE-STAGING' holding ID '$instanceIDofSiteUnderMaintenace', attached successfully to the load balancer"
	     }
	     catch 
	     {
	         echo $_.Exception.ToString()
	         echo "Error occured while attaching the instance 'MICROINSTANCE-STAGING' to load balancer"
	     }		
	}
}

# Function to delete scale up policy request
function DeleteScaleUpPolicyRequestWeb
{
	#Region
	$DeletePolicyRequest = New-Object Amazon.AutoScaling.Model.DeletePolicyRequest
	$DeletePolicyRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$DeletePolicyRequest.PolicyName = $ScaleUpPolicyForWeb
	$ASClient.DeletePolicy($DeletePolicyRequest)
	#EndRegion
}

# Functions to delete scale up policy requests
function DeleteScaleUpPolicyRequestApp
{
	#Region
	$DeletePolicyRequest = New-Object Amazon.AutoScaling.Model.DeletePolicyRequest
	$DeletePolicyRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$DeletePolicyRequest.PolicyName = $ScaleUpPolicyForApp
	$ASClient.DeletePolicy($DeletePolicyRequest)
	#EndRegion
}

# Functions to delete scale down policy requests
function DeleteScaleDownPolicyRequestWeb
{
	#Region
	$DeletePolicyRequest = New-Object Amazon.AutoScaling.Model.DeletePolicyRequest
	$DeletePolicyRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$DeletePolicyRequest.PolicyName = $ScaleDownPolicyForWeb
	$ASClient.DeletePolicy($DeletePolicyRequest)
	#EndRegion
}

function DeleteScaleDownPolicyRequestApp
{
	#Region
	$DeletePolicyRequest = New-Object Amazon.AutoScaling.Model.DeletePolicyRequest
	$DeletePolicyRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$DeletePolicyRequest.PolicyName = $ScaleDownPolicyForApp
	$ASClient.DeletePolicy($DeletePolicyRequest)
	#EndRegion
}

# Functions to delete scale up metric alarm
function DeleteScaleUpMetricAlarm
{
	#Region
	$DeleteAlarmRequest = New-Object Amazon.CloudWatch.Model.DeleteAlarmsRequest
	$AlarmNames = New-Object “System.Collections.Generic.List[String]”
	$AlarmNames.Add($ScaleUpAlarmNameForWeb)
	if($WinServiceFlag -eq 'true')
	{
		$AlarmNames.Add($ScaleUpAlarmNameForApp)
	}
	$DeleteAlarmRequest.AlarmNames = $AlarmNames
    $CWClient.DeleteAlarms($DeleteAlarmRequest)
	
	#EndRegion
}

# Function to delete scale down metric alarm
function DeleteScaleDownMetricAlarm
{
	#Region
	$DeleteAlarmRequest = New-Object Amazon.CloudWatch.Model.DeleteAlarmsRequest
	$AlarmNames = New-Object “System.Collections.Generic.List[String]”
	$AlarmNames.Add($ScaleDownAlarmNameForWeb)
	if($WinServiceFlag -eq 'true')
	{
		$AlarmNames.Add($ScaleDownAlarmNameForApp)
	}
	$DeleteAlarmRequest.AlarmNames = $AlarmNames
	$CWClient.DeleteAlarms($DeleteAlarmRequest)
	#EndRegion
}

# Functions to delete auto scaling group
function DeleteAutoScalingGroupWeb
{
	#Region
	$DeleteAutoScalingGroupRequest = New-Object Amazon.AutoScaling.Model.DeleteAutoScalingGroupRequest
	$DeleteAutoScalingGroupRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$DeleteAutoScalingGroupRequest.ForceDelete = 'true'
	$ASClient.DeleteAutoScalingGroup($DeleteAutoScalingGroupRequest)
	Start-Sleep -s 100
	#EndRegion
}

function DeleteAutoScalingGroupApp
{
	#Region
	$DeleteAutoScalingGroupRequest = New-Object Amazon.AutoScaling.Model.DeleteAutoScalingGroupRequest
	$DeleteAutoScalingGroupRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$DeleteAutoScalingGroupRequest.ForceDelete = 'true'
	$ASClient.DeleteAutoScalingGroup($DeleteAutoScalingGroupRequest)
	Start-Sleep -s 100
	#EndRegion
}

function DeleteAutoScalingGroupZoneBoth
{
	#Region
	$DeleteAutoScalingGroupRequest = New-Object Amazon.AutoScaling.Model.DeleteAutoScalingGroupRequest
	$DeleteAutoScalingGroupRequest.AutoScalingGroupName = $AutoScalingGroupInZoneBoth
	$DeleteAutoScalingGroupRequest.ForceDelete = 'true'
	$ASClient.DeleteAutoScalingGroup($DeleteAutoScalingGroupRequest)
	Start-Sleep -s 100
	#EndRegion
}

# Functions to delete lanuch configurations
function DeleteLaunchConfigurationsWeb
{
	#Region
	$DeleteLaunchConfigurationRequest = New-Object Amazon.AutoScaling.Model.DeleteLaunchConfigurationRequest
	$DeleteLaunchConfigurationRequest.LaunchConfigurationName = $LaunchConfigurationNameWeb
	$ASClient.DeleteLaunchConfiguration($DeleteLaunchConfigurationRequest)
	Start-Sleep -s 100
	#EndRegion
}

function DeleteLaunchConfigurationsApp
{
	#Region
	$DeleteLaunchConfigurationRequest = New-Object Amazon.AutoScaling.Model.DeleteLaunchConfigurationRequest
	$DeleteLaunchConfigurationRequest.LaunchConfigurationName = $LaunchConfigurationNameWinService
	$ASClient.DeleteLaunchConfiguration($DeleteLaunchConfigurationRequest)
	Start-Sleep -s 100
	#EndRegion
}

# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#Delete Route53DomainName
#DeleteLoadBalancerWeb
#DeleteLoadBalancerApp

<#

# Function to delete route53 domain name
function DeleteRoute53DomainName
{
	#Region 
	$OldDNSName = ""
	$Response = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersResponse
	$Response = $ELBClient.DescribeLoadBalancers()
	foreach($LBDescription in $Response.DescribeLoadBalancersResult.LoadBalancerDescriptions)
	{
		if($LBDescription.LoadBalancerName -eq $LBWeb)
		{
			 $OldDNSName = $LBDescription.DNSName
		}
	}
	echo "Old DNS Name : $OldDNSName"
	
	$ChangeResourceRecordSetsRequest = New-Object Amazon.Route53.Model.ChangeResourceRecordSetsRequest
	$RRSet = New-Object Amazon.Route53.Model.ResourceRecordSet
	$RRSet.Name = $Route53DomainName
	$RRSet.Type = $Route53RRSetType	
	$RRSet.TTL = $Route53RRSetTTL	

	$ResourceRecord = New-Object Amazon.Route53.Model.ResourceRecord
	$ResourceRecord.Value = $OldDNSName
	$RRSet.ResourceRecords.Add($ResourceRecord)

	$ChangeItem = New-Object Amazon.Route53.Model.Change
	$ChangeItem.Action = 'DELETE'
	$ChangeItem.ResourceRecordSet = $RRSet

	$ListChanges = New-Object “System.Collections.Generic.List[Amazon.Route53.Model.Change]”
	$ListChanges.Add($ChangeItem)

	$ChangeBatch = New-Object Amazon.Route53.Model.ChangeBatch
	$ChangeBatch.Changes = $ListChanges
	$ChangeBatch.Comment = "Deleting Record Set"

	$ChangeResourceRecordSetsRequest.ChangeBatch = $ChangeBatch
	$ChangeResourceRecordSetsRequest.HostedZoneId = $HostedZoneId
	try
	{
		echo "Domain name $Route53DomainName is Deleting...."
		$Route53Client.ChangeResourceRecordSets($ChangeResourceRecordSetsRequest)
		echo "Domain name $Route53DomainName Deleted Successfully"
	}
	catch
	{
		echo $_.Exception.ToString()
	    echo "Error occured while create route 53 domain name"
	}
	#EndRegion
}

# Functions to delete load balancers
function DeleteLoadBalancerWeb
{
	#Region
	$DeleteLoadBalancerRequest = New-Object Amazon.ElasticLoadBalancing.Model.DeleteLoadBalancerRequest
	$DeleteLoadBalancerRequest.LoadBalancerName = $LBWeb
    try
    {
		echo "$LBWeb is Deleting...."
	    $ELBClient.DeleteLoadBalancer($DeleteLoadBalancerRequest)
		echo "$LBWeb Deleted Successfully"
    }
    catch
    {
        echo "Exception"
        echo $_.Exception.ToString()
    }
	#Endregion
}

function DeleteLoadBalancerApp
{
	#Region
	$DeleteLoadBalancerRequest = New-Object Amazon.ElasticLoadBalancing.Model.DeleteLoadBalancerRequest
	$DeleteLoadBalancerRequest.LoadBalancerName = $LBApp
    try
    {
		echo "$LBApp is Deleting...."
	    $ELBClient.DeleteLoadBalancer($DeleteLoadBalancerRequest)
		echo "$LBApp Deleted Successfully"
    }
    catch
    {
        echo "Exception"
        echo $_.Exception.ToString()
    }
	#Endregion
} 

------#>

#___________________________________________#
#											#
# 	Methods for Build Up Infrastructure		#
#											#
#___________________________________________#


# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#CreateLoadBalancerWeb
#CreateLoadBalancerApp

<#

# Function to create load balance
function CreateLoadBalancerWeb([ref]$LBDNSNameWeb)
{
    #Region

	#PORT AND PROTOCOLS SETTING FOR LOAD BALANCER
    # Initializing HTTPS Listener (with SSL Certificate)
	$Listeners = New-Object “System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Listener]”
	
    $item_SSL = New-Object Amazon.ElasticLoadBalancing.Model.Listener
	$item_SSL.InstancePort = $WebLoadBalancerInstancePort
	$item_SSL.LoadBalancerPort = $WebLoadBalancerPort	
	$item_SSL.Protocol = $WebLoadBalancerProtocol	
	$item_SSL.InstanceProtocol = $WebLoadBalancerInstanceProtocol 
	if($WebLoadBalancerSSLCertificateId -ne 'None' -or $WebLoadBalancerSSLCertificateId -ne 'none' -or $WebLoadBalancerSSLCertificateId -ne '')
    {
        $item_SSL.SSLCertificateId = $WebLoadBalancerSSLCertificateId
    }

    # Initializing HTTP Listener (without SSL Certificate)
    $item_HTTP = New-Object Amazon.ElasticLoadBalancing.Model.Listener
	$item_HTTP.InstancePort = $WebLoadBalancerInstancePort
	$item_HTTP.LoadBalancerPort = $WebLoadBalancerHTTPPort
    $item_HTTP.Protocol = $WebLoadBalancerHTTPProtocol
	$item_HTTP.InstanceProtocol = $WebLoadBalancerInstanceProtocol

	$Listeners.Add($item_SSL)  # Add HTTPS Listener
    $Listeners.Add($item_HTTP) # Add HTTP Listener

	# LOAD BALANCER CONFIGURATIONS
	$Request = New-Object Amazon.ElasticLoadBalancing.Model.CreateLoadBalancerRequest
	$Request.LoadBalancerName = $LBWeb
	$Request.AvailabilityZones = $Zones
	$Request.Scheme = $WebLoadBalancerRequestScheme	
	$Request.Listeners = $Listeners

	#CREATING A LOAD BALANCER
	try
	{
		echo "Load Balancer for Web Creating...."
		$LBResponse = New-Object Amazon.ElasticLoadBalancing.Model.CreateLoadBalancerResponse
		$LBResponse = $ELBClient.CreateLoadBalancer($Request)
		$LBDNSNameWeb.Value = $LBResponse.CreateLoadBalancerResult.DNSName
		echo "Load Balancer for Web Created Successfully"
	}
	catch 
	{		
		echo "Exception"
		echo $_.Exception.ToString()
		echo "Unable To Create Load Balancer due to exception above"

	}

	#EndRegion
}

function CreateLoadBalancerApp([ref]$LBDNSNameApp)
{
    #region
	#PORT AND PROTOCOLS SETTING FOR LOAD BALANCER
	$Listeners = New-Object “System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Listener]”
	$item = New-Object Amazon.ElasticLoadBalancing.Model.Listener
	$item.InstancePort = $AppLoadBalancerInstancePort	
	$item.LoadBalancerPort = $AppLoadBalancerPort	
	$item.Protocol = $AppLoadBalancerProtocol	
	$item.InstanceProtocol = $AppLoadBalancerInstanceProtocol	
	$Listeners.Add($item)

	# LOAD BALANCER CONFIGURATIONS
	$Request = New-Object Amazon.ElasticLoadBalancing.Model.CreateLoadBalancerRequest
	$Request.LoadBalancerName = $LBApp
	$Request.AvailabilityZones = $Zones
	$Request.Scheme = $AppLoadBalancerRequestScheme	
	$Request.Listeners = $Listeners

	    #CREATING A LOAD BALANCER
	    try
	    {
			echo "Load Balancer for App Creating...."
	    	$LBResponse = New-Object Amazon.ElasticLoadBalancing.Model.CreateLoadBalancerResponse
	    	$LBResponse = $ELBClient.CreateLoadBalancer($Request)
	    	$LBDNSNameApp.Value = $LBResponse.CreateLoadBalancerResult.DNSName
	    	echo "Load Balancer Created Successfully for App Server"
	    }
	    catch 
	    {		
	    	echo "Exception"
	    	echo $_.Exception.ToString()
	    	echo "Unable to create Load Balancer due to exception above"
	    
	    }
	#endregion
}

#>

# Function to create launch configuration. these are the congfiguration for launching a new instance when the load will be increased.
function CreateLaunchConfigurationsWeb
{
    #region
	#Launch Configuration Request
	$LaunchConfigurationRequest = New-Object Amazon.AutoScaling.Model.CreateLaunchConfigurationRequest
	$LaunchConfigurationRequest.LaunchConfigurationName = $LaunchConfigurationNameWeb
	$LaunchConfigurationRequest.ImageId = $AMIid
	$LaunchConfigurationRequest.InstanceType = $InstanceType
	$LaunchConfigurationRequest.KeyName = $KeyPairName
	$LaunchConfigurationRequest.SecurityGroups = $SecurityGroup
	$LaunchConfigurationRequest.UserData = $userDataContent
	$LaunchConfigurationResponse = New-Object Amazon.AutoScaling.Model.CreateLaunchConfigurationResponse
	try
	{
		echo "Launch Configuration Creating for Web"
		$LaunchConfigurationResponse = $ASClient.CreateLaunchConfiguration($LaunchConfigurationRequest)
		echo "Launch Configuration for Web Created Successfully"
		echo "Status Code : $LaunchConfigurationResponse.HttpStatusCode"
		echo "Configuration Created! RequestId : $LaunchConfigurationResponse.ResponseMetadata.RequestId"
	}
	catch {
		echo "Exception"
		echo $_.Exception.ToString()
		echo "Unable to create Lunch Configuration due to above exception"
	}
	#endregion
}

function CreateLaunchConfigurationsApp
{
    #region
	$LaunchConfigurationRequestWS = New-Object Amazon.AutoScaling.Model.CreateLaunchConfigurationRequest
	$LaunchConfigurationRequestWS.LaunchConfigurationName = $LaunchConfigurationNameWinService
	$LaunchConfigurationRequestWS.ImageId = $AMIid
	$LaunchConfigurationRequestWS.InstanceType = $InstanceType
	$LaunchConfigurationRequestWS.KeyName = $KeyPairName
	$LaunchConfigurationRequestWS.SecurityGroups = $SecurityGroup
	$LaunchConfigurationRequestWS.UserData = $userDataContentWinService
	$LaunchConfigurationResponse = New-Object Amazon.AutoScaling.Model.CreateLaunchConfigurationResponse
	try
	{
		echo "Launch Configuration Creating for App...."
		$LaunchConfigurationResponse = $ASClient.CreateLaunchConfiguration($LaunchConfigurationRequestWS)
		echo "Launch Configuration for App Created Successfully"
		echo "Status Code : $LaunchConfigurationResponse.HttpStatusCode"
		echo "Configuration Created! RequestId : $LaunchConfigurationResponse.ResponseMetadata.RequestId"
	}
	catch 
	{
		echo "Exception"
		echo $_.Exception.ToString()
		echo "Unable to create Lunch Configuration due to above exception"
	}
	#endregion
}

# Function to create auto scaling groups.
function CreateAutoScalingGroupWeb
{
    #Region
	#LOAD BALANCER LIST
	$LBList = New-Object “System.Collections.Generic.List[String]”
	$LBList.Add($LBWeb);
	
	#Auto Scale Group Request
	$ASRequest = New-Object Amazon.AutoScaling.Model.CreateAutoScalingGroupRequest
	$ASRequest.AvailabilityZones = $Zones;
	$ASRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$ASRequest.LoadBalancerNames = $LBList;
	$ASRequest.LaunchConfigurationName = $LaunchConfigurationNameWeb
	$ASRequest.MinSize = 0;
	$ASRequest.MaxSize = 0;
	
	try
	{
		echo "Auto Scaling Group Creating for Web...."
		$AutoScalingGroupResponse = New-Object Amazon.AutoScaling.Model.CreateAutoScalingGroupResponse
		$ASClient.CreateAutoScalingGroup($ASRequest)
		echo "Auto Scaling Group for Web Created Successfully"
		echo "Status Code : $AutoScalingGroupResponse.HttpStatusCode"
		echo "Configuration Created! RequestId : $AutoScalingGroupResponse.ResponseMetadata.RequestId"
	}
	catch 
	{
		echo "Exception"
		echo $_.Exception.ToString()
	}
	#EndRegion
}

function CreateAutoScalingGroupApp
{
    #region
	#LOAD BALANCER LIST
	$LBList = New-Object “System.Collections.Generic.List[String]”
	$LBList.Add($LBApp);
	
	#Auto Scale Group Request
	$ASRequest = New-Object Amazon.AutoScaling.Model.CreateAutoScalingGroupRequest
	$ASRequest.AvailabilityZones = $Zones;
	$ASRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$ASRequest.LoadBalancerNames = $LBList;
	$ASRequest.LaunchConfigurationName = $LaunchConfigurationNameWinService
	$ASRequest.MinSize = 0;
	$ASRequest.MaxSize = 0;
	
	try
	{
		echo "Auto Scaling Group for App Creating...."
		$AutoScalingGroupResponse = New-Object Amazon.AutoScaling.Model.CreateAutoScalingGroupResponse
		$ASClient.CreateAutoScalingGroup($ASRequest)
		echo "Auto Scaling Group for App Created Successfully"
		echo "Status Code : $AutoScalingGroupResponse.HttpStatusCode"
		echo "Configuration Created! RequestId : $AutoScalingGroupResponse.ResponseMetadata.RequestId"
	}
	catch 
	{
		echo "Exception"
		echo $_.Exception.ToString()
	}
	#endregion
}

# Functions to create Instances in multiple zones
function CreateWebInstancesInMultipleZones($Zone)
{
	#Region	
	$placement = New-Object Amazon.EC2.Model.Placement
	$placement.AvailabilityZone = $Zone
	$runRequest.Placement = $placement
	$runResultFirst = ""
	try	
	{
	   $runRespFirst = $client.RunInstances($runRequest)
	}		
	catch
	{
	    echo $_.Exception.ToString()
	    echo "Unable to launch instances"
	}	
	Start-Sleep -s 1
	$runResultFirst = $runRespFirst.RunInstancesResult.Reservation.RunningInstance[0].InstanceId 			
	$InstanceIdsWeb.add($runResultFirst)
	
	#EndRegion
}

function CreateAppServerInstance([ref]$InstanceIdApp)
{
	#region
	
	$placement = New-Object Amazon.EC2.Model.Placement
	$placement.AvailabilityZone = "eu-west-1a"
	$runRequestWinService.Placement = $placement
	$runResultFirst = ""
	try	
	{
		echo "Launching Instance for App...."
		$runRespFirst = $client.RunInstances($runRequestWinService)
		echo "Launched Instance for App Successfully"
	}
	catch
	{
		echo "Exception"
	    echo $_.Exception.ToString()
	    echo "Unable to launch instance for App"
	}	
	Start-Sleep -s 1
	$runResultFirst = $runRespFirst.RunInstancesResult.Reservation.RunningInstance[0].InstanceId 			
	$InstanceIdApp.Value = $runResultFirst
		
	#endregion
}

# Function to create Tags for all created instances
function CreateInstanceTags
{
	#region

    $WebInstanceIdsAndTags = @(
						    ($InstanceIdsWeb),
						    ($TagValuesWeb)
					    )
   
    for($i=0; $i -lt $Zones.Count; $i++)
    {
        $InstanceIdWeb = $WebInstanceIdsAndTags[0][$i]
        $TagValueWeb = $WebInstanceIdsAndTags[1][$i]

        $InstancesList = New-Object “System.Collections.Generic.List[String]”
	    $InstancesList.Add($InstanceIdWeb)
	    $TagList = New-Object “System.Collections.Generic.List[Amazon.EC2.Model.Tag]”
	    $Tag = New-Object Amazon.EC2.Model.Tag
	    $Tag.Key = "Name"
	    $Tag.Value = $TagValueWeb # ${bamboo.ProjectName} + " " + ${bamboo.buildNumber} # Project-Name + Build Number
	    $TagList.Add($Tag)

	    $TagRequest = New-Object Amazon.EC2.Model.CreateTagsRequest
	    $TagRequest.Resources = $InstancesList
	    $TagRequest.Tags = $TagList

	    try
	    {
		    $EC2Client.CreateTags($TagRequest)
		    echo "Instance Tag for Web Created Successfully: $TagValueWeb"
	    }
	    catch 
	    {
			echo "Exception"
		    echo $_.Exception.ToString()
	    }
    }

	
	if($WinServiceFlag -eq 'true')
	{
		$InstancesList = New-Object “System.Collections.Generic.List[String]”
		$InstancesList.Add($InstanceIdApp)
		$TagList = New-Object “System.Collections.Generic.List[Amazon.EC2.Model.Tag]”
		$Tag = New-Object Amazon.EC2.Model.Tag
		$Tag.Key = "Name"
		$Tag.Value = $TagValueApp # ${bamboo.ProjectName} + " " + ${bamboo.buildNumber} # Project-Name + Build Number
		$TagList.Add($Tag)

		$TagRequest = New-Object Amazon.EC2.Model.CreateTagsRequest
		$TagRequest.Resources = $InstancesList
		$TagRequest.Tags = $TagList

		try
		{
			echo "Instance Tag is Creating for App...."
			$EC2Client.CreateTags($TagRequest)
			echo "Instance Tag for App Created Successfully"
		}
		catch 
		{
			echo $_.Exception.ToString()
		}
	}
	
	#endregion
}

# Functions to create Scale policies
function CreateScaleUpPolicyForWeb([ref]$ScaleUpPolicyARNWeb)
{
	#Region
	#Scale Up Policy Request
	$ScaleUpPolicyRequest = New-Object Amazon.AutoScaling.Model.PutScalingPolicyRequest
	$ScaleUpPolicyRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$ScaleUpPolicyRequest.PolicyName = $ScaleUpPolicyForWeb
	#the cooldown period is used to prevent AWS from executing multiple policies within a very short time.
	$ScaleUpPolicyRequest.Cooldown = $WebScaleUpPolicyRequestCooldown	
	$ScaleUpPolicyRequest.ScalingAdjustment = $WebScaleUpPolicyRequestScalingAdjustment	
	$ScaleUpPolicyRequest.AdjustmentType = $WebScaleUpPolicyRequestAdjustmentType	
	$ScaleUpPolicyResponse = New-Object Amazon.AutoScaling.Model.PutScalingPolicyResponse
	try
	{
		echo "Scale Up Policy Creatign for Web Server...."
		$ScaleUpPolicyResponse = $ASClient.PutScalingPolicy($ScaleUpPolicyRequest)
		$ScaleUpPolicyARNWeb.Value = $ScaleUpPolicyResponse.PutScalingPolicyResult.get_PolicyARN()
		echo "Scale Up Policy for Created for Web Server Successfully"
		echo "Status Code : $ScaleUpPolicyResponse.HttpStatusCode"
	}
	catch 
	{	
		echo $_.Exception.ToString()
		echo "Error occured while Create Scaling Up Policy Request"
	}
	#EndRegion
}

function CreateScaleDownPolicyForWeb([ref]$ScaleDownPolicyARNWeb)
{
	#Region
	#Scale Down Policy Request
	$ScaleDownPolicyRequest = New-Object Amazon.AutoScaling.Model.PutScalingPolicyRequest
	$ScaleDownPolicyRequest.AutoScalingGroupName = $AutoScalingGroupForWeb
	$ScaleDownPolicyRequest.PolicyName = $ScaleDownPolicyForWeb
	#the cooldown period is used to prevent AWS from executing multiple policies within a very short time.
	$ScaleDownPolicyRequest.Cooldown = $WebScaleDownPolicyRequestCooldown	
	$ScaleDownPolicyRequest.ScalingAdjustment = $WebScaleDownPolicyRequestScalingAdjustment	
	$ScaleDownPolicyRequest.AdjustmentType = $WebScaleDownPolicyRequestAdjustmentType	
	$ScaleDownPolicyResponse = New-Object Amazon.AutoScaling.Model.PutScalingPolicyResponse
	try
	{
		echo "Scale Down Policy Creating For Web Server...."
		$ScaleDownPolicyResponse = $ASClient.PutScalingPolicy($ScaleDownPolicyRequest)
	 	$ScaleDownPolicyARNWeb.Value = $ScaleDownPolicyResponse.PutScalingPolicyResult.get_PolicyARN()
		echo "Scale Down Policy Created For Web Server Successfully"
		echo "Status Code : $ScaleDownPolicyResponse.HttpStatusCode"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Down Policy Request"
	}
	#EndRegion
}

function CreateScaleUpPolicyForApp([ref]$ScaleUpPolicyARNApp)
{
	#Region
	#Scale Up Policy Request
	$ScaleUpPolicyRequest = New-Object Amazon.AutoScaling.Model.PutScalingPolicyRequest
	$ScaleUpPolicyRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$ScaleUpPolicyRequest.PolicyName = $ScaleUpPolicyForApp
	#the cooldown period is used to prevent AWS from executing multiple policies within a very short time.
	$ScaleUpPolicyRequest.Cooldown = $AppScaleUpPolicyRequestCooldown	
	$ScaleUpPolicyRequest.ScalingAdjustment = $AppScaleUpPolicyRequestScalingAdjustment	
	$ScaleUpPolicyRequest.AdjustmentType = $AppScaleUpPolicyRequestAdjustmentType	
	$ScaleUpPolicyResponse = New-Object Amazon.AutoScaling.Model.PutScalingPolicyResponse
	try
	{
		echo "Scale Up Policy Creating for App...."
		$ScaleUpPolicyResponse = $ASClient.PutScalingPolicy($ScaleUpPolicyRequest)
		$ScaleUpPolicyARNApp.Value = $ScaleUpPolicyResponse.PutScalingPolicyResult.get_PolicyARN()
		echo "Scale Up Policy Created for App Created Successfully"
		echo "Status Code : $ScaleUpPolicyResponse.HttpStatusCode"
	}
	catch 
	{	
		echo $_.Exception.ToString()
		echo "Error occured while Create Scaling Up Policy Request"
	}
	#EndRegion
}

function CreateScaleDownPolicyForApp([ref]$ScaleDownPolicyARNApp)
{
	#Region
	#Scale Down Policy Request
	$ScaleDownPolicyRequest = New-Object Amazon.AutoScaling.Model.PutScalingPolicyRequest
	$ScaleDownPolicyRequest.AutoScalingGroupName = $AutoScalingGroupForApp
	$ScaleDownPolicyRequest.PolicyName = $ScaleDownPolicyForApp
	#the cooldown period is used to prevent AWS from executing multiple policies within a very short time.
	$ScaleDownPolicyRequest.Cooldown = $AppScaleDownPolicyRequestCooldown	
	$ScaleDownPolicyRequest.ScalingAdjustment = $AppScaleDownPolicyRequestScalingAdjustment	
	$ScaleDownPolicyRequest.AdjustmentType = $AppScaleDownPolicyRequestAdjustmentType	
	$ScaleDownPolicyResponse = New-Object Amazon.AutoScaling.Model.PutScalingPolicyResponse
	try
	{
		echo "Scale Down Policy Creating for App...."
		$ScaleDownPolicyResponse = $ASClient.PutScalingPolicy($ScaleDownPolicyRequest)
	 	$ScaleDownPolicyARNApp.Value = $ScaleDownPolicyResponse.PutScalingPolicyResult.get_PolicyARN()
		echo "Scale Down Policy Created for App Successfully"
		echo "Status Code : $ScaleDownPolicyResponse.HttpStatusCode"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Down Policy Request"
	}
	#EndRegion
}

# Functions to create Matric alarms
function CreateScaleUpMetricAlarmForWeb
{
	#Region
	# Metric Alarm Scale Up
	# “If the average CPU utilization of instance i-37b12752 is measured at 80%
	# or greater 3 times over 3 minutes, then trigger our scale-up policy.”
	$AlarmScaleUp = New-Object Amazon.CloudWatch.Model.PutMetricAlarmRequest
	$AlarmScaleUp.AlarmName = $ScaleUpAlarmNameForWeb
	$AlarmScaleUp.AlarmDescription = $ScaleUpAlarmDescription
	$AlarmScaleUp.MetricName = $ScaleUpMetricName
	$AlarmScaleUp.Namespace = $WebAlarmScaleUpNamespace	
	$AlarmScaleUp.Statistic = $WebAlarmScaleUpStatistic	
	$AlarmScaleUp.Period = $ScaleUpPeriod
	$AlarmScaleUp.Threshold = $ScaleUpThreshold
	$AlarmScaleUp.ComparisonOperator = $ScaleUpComparisonOperator
	$AlarmScaleUp.EvaluationPeriods = $ScaleUpEvaluationPeriods
	$AlarmScaleUp.Unit = $ScaleUpUnit
	
	$Dimensions = New-Object “System.Collections.Generic.List[Amazon.CloudWatch.Model.Dimension]”	
	foreach($InstanceIdWeb in $InstanceIdsWeb)
	{
		$DItem = New-Object Amazon.CloudWatch.Model.Dimension
		$DItem.Name = "$InstanceIdWeb"
		$DItem.Value = $InstanceIdWeb
		$Dimensions.Add($DItem)
	}
	$ScaleUpActions = New-Object “System.Collections.Generic.List[String]”
	$ScaleUpActions.Add($ScaleUpPolicyARNWeb)
	$AlarmScaleUp.Dimensions = $Dimensions;
	$AlarmScaleUp.AlarmActions = $ScaleUpActions;
	
	$ScaleUpMetricAlarmResponse = New-Object Amazon.CloudWatch.Model.PutMetricAlarmResponse
	try
	{
		echo "Scale up alarm creating for Web...."
		$ScaleUpMetricAlarmResponse = $CWClient.PutMetricAlarm($AlarmScaleUp)
		echo "Scale up alarm created for Web Successfully"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Up Metric Alarm"
	}
	#EndRegion
}

function CreateScaleDownMetricAlarmForWeb
{
    #Region
	# Metric Alarm Scale Down
	# we used to terminate one of the servers if the CPU utilization drops below an average of 20% over 3 minutes.
	$AlarmScaleDown = New-Object Amazon.CloudWatch.Model.PutMetricAlarmRequest
	$AlarmScaleDown.AlarmName = $ScaleDownPolicyARNWeb
	$AlarmScaleDown.AlarmDescription = $ScaleDownAlarmDescription
	$AlarmScaleDown.MetricName = $ScaleDownMetricName
	$AlarmScaleDown.Namespace = $WebAlarmScaleDownNamespace	
	$AlarmScaleDown.Statistic = $WebAlarmScaleDownStatistic	
	$AlarmScaleDown.Period = $ScaleDownPeriod
	$AlarmScaleDown.Threshold = $ScaleDownThreshold
	$AlarmScaleDown.ComparisonOperator = $ScaleDownComparisonOperator
	$AlarmScaleDown.EvaluationPeriods = $ScaleDownEvaluationPeriods
	$AlarmScaleDown.Unit = $ScaleDownUnit
	$ScaleDownActions = New-Object “System.Collections.Generic.List[String]”
    $ScaleDownActions.Add($ScaleDownPolicyARNWeb)
	
	$Dimensions = New-Object “System.Collections.Generic.List[Amazon.CloudWatch.Model.Dimension]”
	foreach($InstanceIdWeb in $InstanceIdsWeb)
	{
		$DItem = New-Object Amazon.CloudWatch.Model.Dimension
		$DItem.Name = "$InstanceIdWeb"
		$DItem.Value = $InstanceIdWeb
		$Dimensions.Add($DItem)
	}
	$AlarmScaleDown.Dimensions = $Dimensions
	$AlarmScaleDown.AlarmActions = $ScaleDownActions
	
	$ScaleDownMetricAlarmResponse = New-Object Amazon.CloudWatch.Model.PutMetricAlarmResponse
	try 
	{
		echo "Scale down alarm creating for Web...."
		$ScaleDownMetricAlarmResponse = $CWClient.PutMetricAlarm($AlarmScaleDown)
		echo "Scale down alarm created for Web Successfully"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Down Metric Alarm"
	}
	#EndRegion
}
function CreateScaleUpMetricAlarmForApp
{
	#Region
	# Metric Alarm Scale Up
	# “If the average CPU utilization of instance i-37b12752 is measured at 80%
	# or greater 3 times over 3 minutes, then trigger our scale-up policy.”
	$AlarmScaleUp = New-Object Amazon.CloudWatch.Model.PutMetricAlarmRequest
	$AlarmScaleUp.AlarmName = $ScaleUpAlarmNameForApp
	$AlarmScaleUp.AlarmDescription = $ScaleUpAlarmDescription
	$AlarmScaleUp.MetricName = $ScaleUpMetricName
	$AlarmScaleUp.Namespace = $AppAlarmScaleUpNamespace	
	$AlarmScaleUp.Statistic = $AppAlarmScaleUpStatistic	
	$AlarmScaleUp.Period = $ScaleUpPeriod
	$AlarmScaleUp.Threshold = $ScaleUpThreshold
	$AlarmScaleUp.ComparisonOperator =$ScaleUpComparisonOperator
	$AlarmScaleUp.EvaluationPeriods = $ScaleUpEvaluationPeriods
	$AlarmScaleUp.Unit = $ScaleUpUnit
	$Dimensions = New-Object “System.Collections.Generic.List[Amazon.CloudWatch.Model.Dimension]”
	$DItem = New-Object Amazon.CloudWatch.Model.Dimension
	$DItem.Name = "$InstanceIdApp"
	$DItem.Value = $InstanceIdApp
	$Dimensions.Add($DItem)
	$ScaleUpActions = New-Object “System.Collections.Generic.List[String]”
	$ScaleUpActions.Add($ScaleUpPolicyARNApp)
	$AlarmScaleUp.Dimensions = $Dimensions;
	$AlarmScaleUp.AlarmActions = $ScaleUpActions;
	
	$ScaleUpMetricAlarmResponse = New-Object Amazon.CloudWatch.Model.PutMetricAlarmResponse
	try
	{
		echo "Scale up alarm creating for App...."
		$ScaleUpMetricAlarmResponse = $CWClient.PutMetricAlarm($AlarmScaleUp)
		echo "Scale up alarm created for App Successfully"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Up Metric Alarm"
	}
	#EndRegion
}

function CreateScaleDownMetricAlarmForApp
{
    #Region
	# Metric Alarm Scale Down
	# we used to terminate one of the servers if the CPU utilization drops below an average of 20% over 3 minutes.
	$AlarmScaleDown = New-Object Amazon.CloudWatch.Model.PutMetricAlarmRequest
	$AlarmScaleDown.AlarmName = $ScaleDownAlarmNameForApp
	$AlarmScaleDown.AlarmDescription = $ScaleDownAlarmDescription
	$AlarmScaleDown.MetricName = $ScaleDownMetricName
	$AlarmScaleDown.Namespace = $AppAlarmScaleDownNamespace	
	$AlarmScaleDown.Statistic = $AppAlarmScaleDownStatistic	
	$AlarmScaleDown.Period = $ScaleDownPeriod
	$AlarmScaleDown.Threshold = $ScaleDownThreshold
	$AlarmScaleDown.ComparisonOperator = $ScaleDownComparisonOperator
	$AlarmScaleDown.EvaluationPeriods = $ScaleDownEvaluationPeriods
	$AlarmScaleDown.Unit = $ScaleDownUnit
	$ScaleDownActions = New-Object “System.Collections.Generic.List[String]”
    $ScaleDownActions.Add($ScaleDownPolicyARNApp)
	
	$Dimensions = New-Object “System.Collections.Generic.List[Amazon.CloudWatch.Model.Dimension]”
	$DItem = New-Object Amazon.CloudWatch.Model.Dimension
	$DItem.Name = "$InstanceIdApp"
	$DItem.Value = $InstanceIdApp
	$Dimensions.Add($DItem)
	$AlarmScaleDown.Dimensions = $Dimensions
	$AlarmScaleDown.AlarmActions = $ScaleDownActions
	
	$ScaleDownMetricAlarmResponse = New-Object Amazon.CloudWatch.Model.PutMetricAlarmResponse
	try 
	{
		echo "Scale down alarm creating for App...."
		$ScaleDownMetricAlarmResponse = $CWClient.PutMetricAlarm($AlarmScaleDown)
		echo "Scale down alarm created for App Successfully"
	}
	catch 
	{
	    echo $_.Exception.ToString()
	    echo "Error occured while Create Scaling Down Metric Alarm"
	}
	#EndRegion
}

# Function to Add all instances to related Load balancers
function AddInstanceToaLoadBalancer
{
	#Region

    # This section Detaches (DEREGISTERS) the temporary instance from the LoadBalancer.
    # The instance will have a simple page on IIS. The page will show a maintenance message for the users, in order to cover the downtime of site while it is being under deployment process.
        #First get the ID from file in which it is stored by previous script (MicroInstance.CreateAndStart.ps1)
        $fileName = "MicroInstanceID.txt"
        if(Test-Path ${bamboo.build.working.directory}\$fileName)
        {
            $instanceIDofSiteUnderMaintenace = Get-Content ${bamboo.build.working.directory}\$fileName
        }

        #Code to DeRegister MICROINSTANCE-STAGING (or LIVE or SANDBOX or SiteUnderMaintenance) Instance from Loadbalancer
        $DeregisterInstancesRequest = New-Object Amazon.ElasticLoadBalancing.Model.DeregisterInstancesFromLoadBalancerRequest
        $Instances = New-Object System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Instance]
        $Instance = New-Object Amazon.ElasticLoadBalancing.Model.Instance

        $Instance.InstanceId = $instanceIDofSiteUnderMaintenace
        $Instances.Add($Instance) #add instance to its list
	    $DeregisterInstancesRequest.Instances = $Instances
        $DeregisterInstancesRequest.LoadBalancerName = $LBWeb
        
	    try 
	    {
            echo "Removing the temporary instance 'MICROINSTANCE-STAGING' from load balancer now"
	        $ELBClient.DeregisterInstancesFromLoadBalancer($DeregisterInstancesRequest)
	        echo "The instance 'MICROINSTANCE-STAGING' holding ID '$instanceIDofSiteUnderMaintenace', deregistered/detached successfully from the load balancer"
	    }
	    catch 
	    {
	        echo $_.Exception.ToString()
	        echo "Error occured while attaching the instance 'MICROINSTANCE-STAGING' to load balancer"
	    }
    
    # Now register the original instances with Load Balancer
	$elbRequest = New-Object Amazon.ElasticLoadBalancing.Model.RegisterInstancesWithLoadBalancerRequest
	$elbRequest.LoadBalancerName = $LBWeb

	$instances = New-Object System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Instance]
	foreach($InstanceIdWeb in $InstanceIdsWeb)
	{
		$instance = New-Object Amazon.ElasticLoadBalancing.Model.Instance
		$instance.InstanceId = $InstanceIdWeb
		$instances.add($instance)
	}
	$elbRequest.Instances = $instances
	
	try
	{
		echo "Instances are adding to a load balancer $LBWeb...." 
		$elbResponse = $ELBClient.RegisterInstancesWithLoadBalancer($elbRequest)
		echo "Instances added to a load balancer $LBWeb Successfully" 
	}
	catch 
	{
		echo $_.Exception.ToString()
	    echo "Error occured while adding instances to a load balancer"
	}
	
	if($WinServiceFlag -eq 'true')
	{
		$elbRequest = New-Object Amazon.ElasticLoadBalancing.Model.RegisterInstancesWithLoadBalancerRequest
		$elbRequest.LoadBalancerName = $LBApp

		$instances = New-Object System.Collections.Generic.List[Amazon.ElasticLoadBalancing.Model.Instance]
		$instance = New-Object Amazon.ElasticLoadBalancing.Model.Instance
		$instance.InstanceId = $InstanceIdApp
		$instances.add($instance)
		 
		$elbRequest.Instances = $instances
		
		try
		{
			echo "Instance is adding to a load balancer $LBApp...." 
			$elbResponse = $ELBClient.RegisterInstancesWithLoadBalancer($elbRequest)
			echo "Instance added to a load balancer $LBApp Successfully" 
		}
		catch 
		{
			echo $_.Exception.ToString()
			echo "Error occured while adding instances to a load balancer in zone"
		}
	}

	#EndRegion
}


# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#CreateRoute53DomainName
<#
# Function to create Route53 domain name
function CreateRoute53DomainName
{
	$DNSName = ""
	$Response = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersResponse
	$Response = $ELBClient.DescribeLoadBalancers()
	foreach($LBDescription in $Response.DescribeLoadBalancersResult.LoadBalancerDescriptions)
	{
		if($LBDescription.LoadBalancerName -eq $LBWeb)
		{
			$DNSName = $LBDescription.DNSName
		}
	}
	echo "DNS Name : $DNSName"		
	echo "Creating Route 53 Domain"
	
	$ChangeResourceRecordSetsRequest = New-Object Amazon.Route53.Model.ChangeResourceRecordSetsRequest
	$RRSet = New-Object Amazon.Route53.Model.ResourceRecordSet
	$RRSet.Name = $Route53DomainName
	$RRSet.Type = $Route53RRSetType	
	$RRSet.TTL = $Route53RRSetTTL	
	
	$ResourceRecord = New-Object Amazon.Route53.Model.ResourceRecord
	$ResourceRecord.Value = $DNSName
	$RRSet.ResourceRecords.Add($ResourceRecord)
	
	
	$ChangeItem = New-Object Amazon.Route53.Model.Change
	$ChangeItem.Action = 'CREATE'
	$ChangeItem.ResourceRecordSet = $RRSet
	
	$ListChanges = New-Object “System.Collections.Generic.List[Amazon.Route53.Model.Change]”
	$ListChanges.Add($ChangeItem)
	
	$ChangeBatch = New-Object Amazon.Route53.Model.ChangeBatch
	$ChangeBatch.Changes = $ListChanges
	$ChangeBatch.Comment = "Creating New Record Set"
	
	$ChangeResourceRecordSetsRequest.ChangeBatch = $ChangeBatch
	$ChangeResourceRecordSetsRequest.HostedZoneId = $HostedZoneId
	try
	{
		echo "Domain name $Route53DomainName is Creating...."
		$Route53Client.ChangeResourceRecordSets($ChangeResourceRecordSetsRequest)
		echo "Domain name created $Route53DomainName"
	}
	catch
	{
		echo $_.Exception.ToString()
		echo "Error occured while create route 53 domain name"	
	}
}

 #endregion

#>

#____________________________________________#
<# Buildup infrastructure process sequence

1. Create load balancer
2. Launch configurations
3. Create Autoscaling groups
4. Create Autoscaling policies
5. Create instances 

#>

#_______________________________________________________#
#														#
# 	Process for TearDown the complete Infrastructure	#
#														#
#_______________________________________________________#														

#### STEP 1 ####
# Terminate instances
TerminateInstances


#### STEP 2 ####
# Delete Scale policies
$PoliciesResponse = New-Object Amazon.AutoScaling.Model.DescribePoliciesResponse
$PoliciesResponse = $ASClient.DescribePolicies()
$PUWebFlag = 'false'
foreach($PolicyDescription in $PoliciesResponse.DescribePoliciesResult.ScalingPolicies)
{
	if($PolicyDescription.PolicyName -eq $ScaleUpPolicyForWeb)
	{
		$ScaleUpPolicyARNWeb = $PolicyDescription.PolicyARN
		$PUWebFlag = 'true'
		echo "Scale Up Policy already exist for Web Server"
		DeleteScaleUpPolicyRequestWeb
		echo "Scale Up Policy for Web Server Deleted Successfully"
	}
}

$PDWebFlag = 'false'
foreach($PolicyDescription in $PoliciesResponse.DescribePoliciesResult.ScalingPolicies)
{
	if($PolicyDescription.PolicyName -eq $ScaleDownPolicyForWeb)
	{
		$PDWebFlag = 'true'
		$ScaleDownPolicyARNWeb = $PolicyDescription.PolicyARN
		echo "Scale down policy already exist for Web Server"
		DeleteScaleDownPolicyRequestWeb
		echo "Scale down Policy for Web Server Deleted Successfully"
	}
}

$PoliciesResponse = New-Object Amazon.AutoScaling.Model.DescribePoliciesResponse
$PoliciesResponse = $ASClient.DescribePolicies()
$PUAppFlag = 'false'
foreach($PolicyDescription in $PoliciesResponse.DescribePoliciesResult.ScalingPolicies)
{
	if($PolicyDescription.PolicyName -eq $ScaleUpPolicyForApp)
	{
		$ScaleUpPolicyARNApp = $PolicyDescription.PolicyARN
		$PUAppFlag = 'true'
		echo "Scale Up Policy for App server already exist"
		DeleteScaleUpPolicyRequestApp
		echo "Scale Up Policy for App Server Deleted Successfully"
	}
}

$PDAppFlag = 'false'
foreach($PolicyDescription in $PoliciesResponse.DescribePoliciesResult.ScalingPolicies)
{
	if($PolicyDescription.PolicyName -eq $ScaleDownPolicyForApp)
	{
		$PDAppFlag = 'true'
		$ScaleDownPolicyARNApp = $PolicyDescription.PolicyARN
		echo "Scale down policy already exist for App server"
		DeleteScaleDownPolicyRequestApp
		echo "Scale down Policy for App Server Deleted Successfully"
	}
}

echo "Deleting Scale Up Metric Alarms...."
DeleteScaleUpMetricAlarm
echo "Scale Up Metric Alarms Deleted Successfully"

echo "Deleting Scale Down Metric Alarms...."
DeleteScaleDownMetricAlarm
echo "Scale down Metric Alarms Deleted Successfully"


#### STEP 3 $ 4 ####
# Delete Auto scaling groups and Launch configurations
$LCRequest = New-Object Amazon.AutoScaling.Model.DescribeLaunchConfigurationsRequest
$ListLC = New-Object “System.Collections.Generic.List[String]”
$ListLC.Add($LaunchConfigurationNameWeb)
$ListLC.Add($LaunchConfigurationNameWinService)

$LCRequest.LaunchConfigurationNames = $ListLC;
$LCResponse = New-Object Amazon.AutoScaling.Model.DescribeLaunchConfigurationsResponse
$LCResponse = $ASClient.DescribeLaunchConfigurations($LCRequest)

$FlagLCWeb = 'false' # Launch Configuration for web
$FlagLCApp = 'false' # Launch Confgiuration for window service / app
if ($LCResponse.DescribeLaunchConfigurationsResult.LaunchConfigurations.Count -ge 1)
{
	foreach($LC in $LCResponse.DescribeLaunchConfigurationsResult.LaunchConfigurations)
	{
		echo $LC.LaunchConfigurationName
		if($LC.LaunchConfigurationName -eq $LaunchConfigurationNameWeb)
		{
			$FlagLCWeb = 'true'
			echo "Launch Configuration Web application already exist"	
			# This LaunchConfigurationName for web will be deleteing after the Auto scaling group deleted, because it is attached
		}
		if($LC.LaunchConfigurationName -eq $LaunchConfigurationNameWinService)
		{
			$FlagLCApp = 'true'
			echo "Launch Configuration Win Service already exist"	
			# This LaunchConfigurationName for win service will be deleteing after the Auto scaling group deleted, because it is attached		
		}
	}
}

# delete auto scaling groups before deleting LaunchConfigurationNames, because they are attached

$DASRequest = New-Object Amazon.AutoScaling.Model.DescribeAutoScalingGroupsRequest
$DASResponse = New-Object Amazon.AutoScaling.Model.DescribeAutoScalingGroupsResponse
$DASResponse = $ASClient.DescribeAutoScalingGroups($DASRequest)

$FlagA= 'false'
$FlagB = 'false'
if ($DASResponse.DescribeAutoScalingGroupsResult.AutoScalingGroups.Count -ge 1)
{
	foreach($AS in $DASResponse.DescribeAutoScalingGroupsResult.AutoScalingGroups)
	{
		if($AS.AutoScalingGroupName -eq $AutoScalingGroupForWeb)
		{
			$FlagA = 'true'
			echo "Auto Scaling Group Already Exist For Web"
			DeleteAutoScalingGroupWeb
			echo "Auto Scaling Group for Web Deleted Successfully"
		}
		if($AS.AutoScalingGroupName -eq $AutoScalingGroupForApp)
		{
			$FlagB = 'true'
			echo "Auto Scaling Group Already Exist For App"
			DeleteAutoScalingGroupApp
			echo "Auto Scaling Group for App Deleted Successfully"
		}
	}
}

# Now the LaunchConfigurationName for web and app will be deleted

if($FlagLCWeb -eq 'true')
{
	DeleteLaunchConfigurationsWeb
	echo "Launch Configuration for Web Deleted Successfully"
}
if($FlagLCApp -eq 'true')
{
	DeleteLaunchConfigurationsApp
	echo "Launch Configuration for App Deleted Successfully"
}


# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#DeleteRoute53DomainName
#DeleteLoadBalancerWeb
#DeleteLoadBalancerApp

<#

##### STEP 5 ####
# Delete Rout 53 domain
$ListRecordSetRequest = New-Object Amazon.Route53.Model.ListResourceRecordSetsRequest
$ListRecordSetRequest.HostedZoneId = $HostedZoneId
$DAFlag = 'false'
$ListRecordSetResponse = $Route53Client.ListResourceRecordSets($ListRecordSetRequest)
foreach($RRSet in $ListRecordSetResponse.ListResourceRecordSetsResult.ResourceRecordSets)
{
	if($RRSet.get_Name().ToString() -eq $Route53DomainName+".")
	{
		$DAFlag = 'true'
		echo "Route 53 domain already exist"
		DeleteRoute53DomainName
	}
}



#### STEP 6 ####
# Delete Load balancer
$Response = New-Object Amazon.ElasticLoadBalancing.Model.DescribeLoadBalancersResponse
$Response = $ELBClient.DescribeLoadBalancers()
$FlagA = 'false'
$FlagB = 'false'
foreach($LBDescription in $Response.DescribeLoadBalancersResult.LoadBalancerDescriptions)
{
	if($LBDescription.LoadBalancerName -eq $LBWeb)
	{
	    $LBDNSNameWeb = $LBDescription.DNSName
	    $FlagA = 'true'
		echo "Load balancer already exist with a name $LBWeb"
		DeleteLoadBalancerWeb
	}

	if($LBDescription.LoadBalancerName -eq $LBApp)
	{
	    $LBDNSNameApp = $LBDescription.DNSName
	    $FlagB = 'true'
		echo "Load balancer already exist with a name $LBApp"
		DeleteLoadBalancerApp
	}
}

#>


#___________________________________________#
#											#
# 	Process for Build Up Infrastructure		#
#											#
#___________________________________________#


# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#CreateLoadBalancerWeb
#CreateLoadBalancerApp

<#
#### STEP 1 ####
#Create load balancer - DO NOT DELETE THE EXISTING LBs
CreateLoadBalancerWeb([ref]$LBDNSNameWeb)
if($WinServiceFlag -eq 'true')
{
	CreateLoadBalancerApp([ref]$LBDNSNameApp)
}
#>

#### STEP 2 #### 
#Launch configurations
CreateLaunchConfigurationsWeb
if($WinServiceFlag -eq 'true')
{
	CreateLaunchConfigurationsApp
}

CreateAutoScalingGroupWeb
if($WinServiceFlag -eq 'true')
{
	CreateAutoScalingGroupApp
}

#### STEP 3 #### 
#Create Instances and instance's Tags
echo "Launching Instances for Web in Multiple Zones...."
foreach($Zone in $Zones)
{	
	CreateWebInstancesInMultipleZones($Zone)
}
echo "Launched Instances in Multiple Zones Successfully"
if($WinServiceFlag -eq 'true')
{
	CreateAppServerInstance([ref]$InstanceIdApp)
}

echo "Instance Tags are Creating for Web...."
CreateInstanceTags
Start-Sleep -s 100


#### STEP 4, 5 #### 
# Create Scale up and down policies
echo "Creating scale up policy for web server...."
CreateScaleUpPolicyForWeb([ref]$ScaleUpPolicyARNWeb)

echo "Creating scale down policy for web server...."
CreateScaleDownPolicyForWeb([ref]$ScaleDownPolicyARNWeb)

if($WinServiceFlag -eq 'true')
{
	echo "Creating scale up policy for app server...."
	CreateScaleUpPolicyForApp([ref]$ScaleUpPolicyARNApp)
}

if($WinServiceFlag -eq 'true')
{
	echo "Creating scale down policy for app server...."
	CreateScaleDownPolicyForApp([ref]$ScaleDownPolicyARNApp)
}

#### STEP 6 #### 
# Create Metric alarms
CreateScaleUpMetricAlarmForWeb
CreateScaleDownMetricAlarmForWeb
if($WinServiceFlag -eq 'true')
{
	CreateScaleUpMetricAlarmForApp
	CreateScaleDownMetricAlarmForApp
}


#### STEP 7 #### 
#Add instances to a load balancer
# but wait for at least 2 minutes before detaching the SiteMaintenance Instance and attaching the origingal intances.
Start-Sleep -s 120
AddInstanceToaLoadBalancer


# NOT TO USE THIS SECTION, IN CASE OF 'THS'
# commented out
#CreateRoute53DomainName

<#
#### STEP 8 #### 
# Create Route53 domain name - DO NOT DELETE THE EXISTING ROUTE53 DOMAIN NAME
CreateRoute53DomainName
#>

echo "You're Done. Infrastructure Build Successfully,"
echo "The site '$Route53DomainName' will be available after few minutes :)"
## ===================================================================