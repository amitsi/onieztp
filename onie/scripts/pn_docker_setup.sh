#!/bin/sh

if [ -z "$1" ]
  then
	echo "Usage: $0 <port_num>"
	exit 1
  fi
HTTP_PORT=$1

SCRIPT_COMMIT_SHA=490beaa

# This value will automatically get changed for:
#   * edge
#   * test
#   * experimental
DEFAULT_CHANNEL_VALUE="edge"
if [ -z "$CHANNEL" ]; then
	CHANNEL=$DEFAULT_CHANNEL_VALUE
fi

DOWNLOAD_URL="https://download.docker.com"

# TODO: Remove *-ubuntu-yakkety once 17.07.0-ce hits GA
SUPPORT_MAP="
x86_64-centos-7
x86_64-fedora-24
x86_64-fedora-25
x86_64-fedora-26
x86_64-debian-wheezy
x86_64-debian-jessie
x86_64-debian-stretch
x86_64-ubuntu-trusty
x86_64-ubuntu-xenial
x86_64-ubuntu-yakkety
x86_64-ubuntu-zesty
s390x-ubuntu-xenial
s390x-ubuntu-yakkety
s390x-ubuntu-zesty
ppc64le-ubuntu-xenial
ppc64le-ubuntu-zesty
aarch64-ubuntu-xenial
armv6l-raspbian-jessie
armv7l-raspbian-jessie
armv6l-raspbian-stretch
armv7l-raspbian-stretch
armv7l-debian-jessie
armv7l-debian-stretch
armv7l-ubuntu-trusty
armv7l-ubuntu-xenial
armv7l-ubuntu-yakkety
armv7l-ubuntu-zesty
"

mirror=''
DRY_RUN=${DRY_RUN:-}
while [ $# -gt 0 ]; do
	case "$1" in
		--mirror)
			mirror="$2"
			shift
			;;
		--dry-run)
			DRY_RUN=1
			;;
		--*)
			echo "Illegal option $1"
			;;
	esac
	shift $(( $# > 0 ? 1 : 0 ))
done

case "$mirror" in
	Aliyun)
		DOWNLOAD_URL="https://mirrors.aliyun.com/docker-ce"
		;;
	AzureChinaCloud)
		DOWNLOAD_URL="https://mirror.azure.cn/docker-ce"
		;;
esac

docker_key="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

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
EJOQTvBR8Q==
=Yhur
-----END PGP PUBLIC KEY BLOCK-----
"

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

is_dry_run() {
	if [ -z "$DRY_RUN" ]; then
		return 1
	else
		return 0
	fi
}

get_distribution() {
	lsb_dist=""
	# Every system that we officially support has /etc/os-release
	if [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
	fi
	# Returning an empty string here should be alright since the
	# case statements don't act unless you provide an actual value
	echo "$lsb_dist"
}

echo_docker_as_nonroot() {
	if is_dry_run; then
		return
	fi
	if command_exists docker && [ -e /var/run/docker.sock ]; then
		(
			set -x
			$sh_c 'docker version'
		) || true
	fi
	your_user=your-user
	[ "$user" != 'root' ] && your_user="$user"
	# intentionally mixed spaces and tabs here -- tabs are stripped by "<<-EOF", spaces are kept in the output
	echo "If you would like to use Docker as a non-root user, you should now consider"
	echo "adding your user to the \"docker\" group with something like:"
	echo
	echo "  sudo usermod -aG docker $your_user"
	echo
	echo "Remember that you will have to log out and back in for this to take effect!"
	echo
	echo "WARNING: Adding a user to the \"docker\" group will grant the ability to run"
	echo "         containers which can be used to obtain root privileges on the"
	echo "         docker host."
	echo "         Refer to https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface"
	echo "         for more information."

}

# Check if this is a forked Linux distro
check_forked() {

	# Check for lsb_release command existence, it usually exists in forked distros
	if command_exists lsb_release; then
		# Check if the `-u` option is supported
		set +e
		lsb_release -a -u > /dev/null 2>&1
		lsb_release_exit_code=$?
		set -e

		# Check if the command has exited successfully, it means we're in a forked distro
		if [ "$lsb_release_exit_code" = "0" ]; then
			# Print info about current distro
			cat <<-EOF
			You're using '$lsb_dist' version '$dist_version'.
			EOF

			# Get the upstream release info
			lsb_dist=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'id' | cut -d ':' -f 2 | tr -d '[:space:]')
			dist_version=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'codename' | cut -d ':' -f 2 | tr -d '[:space:]')

			# Print info about upstream distro
			cat <<-EOF
			Upstream release is '$lsb_dist' version '$dist_version'.
			EOF
		else
			if [ -r /etc/debian_version ] && [ "$lsb_dist" != "ubuntu" ] && [ "$lsb_dist" != "raspbian" ]; then
				# We're Debian and don't even know it!
				lsb_dist=debian
				dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
				case "$dist_version" in
					9)
						dist_version="stretch"
					;;
					8|'Kali Linux 2')
						dist_version="jessie"
					;;
					7)
						dist_version="wheezy"
					;;
				esac
			fi
		fi
	fi
}

semverParse() {
	major="${1%%.*}"
	minor="${1#$major.}"
	minor="${minor%%.*}"
	patch="${1#$major.$minor.}"
	patch="${patch%%[-.]*}"
}

ee_notice() {
	echo
	echo
	echo "  WARNING: $1 is now only supported by Docker EE"
	echo "           Check https://store.docker.com for information on Docker EE"
	echo
	echo
}

do_install() {

	if command_exists docker; then
		return
	fi

	echo "========================================================================="
	echo "# Executing docker install script, commit: $SCRIPT_COMMIT_SHA"
	echo "========================================================================="

	user="$(id -un 2>/dev/null || true)"

	sh_c='sh -c'
	if [ "$user" != 'root' ]; then
		if command_exists sudo; then
			sh_c='sudo -E sh -c'
		elif command_exists su; then
			sh_c='su -c'
		else
			cat >&2 <<-'EOF'
			Error: this installer needs the ability to run commands as root.
			We are unable to find either "sudo" or "su" available to make this happen.
			EOF
			exit 1
		fi
	fi

	if is_dry_run; then
		sh_c="echo"
	fi

	# perform some very rudimentary platform detection
	lsb_dist=$( get_distribution )
	lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"

	case "$lsb_dist" in

		ubuntu)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
				dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
			fi
		;;

		debian|raspbian)
			dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
			case "$dist_version" in
				9)
					dist_version="stretch"
				;;
				8)
					dist_version="jessie"
				;;
				7)
					dist_version="wheezy"
				;;
			esac
		;;

		centos)
			if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
				dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
			fi
		;;

		rhel|ol|sles)
			ee_notice "$lsb_dist"
			exit 1
			;;

		*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
				dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
			fi
		;;

	esac

	# Check if this is a forked Linux distro
	check_forked

	# Check if we actually support this configuration
	if ! echo "$SUPPORT_MAP" | grep "$(uname -m)-$lsb_dist-$dist_version" >/dev/null; then
		cat >&2 <<-'EOF'

		Either your platform is not easily detectable or is not supported by this
		installer script.
		Please visit the following URL for more detailed installation instructions:

		https://docs.docker.com/engine/installation/

		EOF
		exit 1
	fi

	# Run setup for each distro accordingly
	case "$lsb_dist" in
		ubuntu|debian)
			pre_reqs="apt-transport-https ca-certificates curl"
			if [ "$lsb_dist" = "debian" ] && [ "$dist_version" = "wheezy" ]; then
				pre_reqs="$pre_reqs python-software-properties"
				backports="deb http://ftp.debian.org/debian wheezy-backports main"
				if ! grep -Fxq "$backports" /etc/apt/sources.list; then
					(set -x; $sh_c "echo \"$backports\" >> /etc/apt/sources.list")
				fi
			else
				pre_reqs="$pre_reqs software-properties-common"
			fi
			if ! command -v gpg > /dev/null; then
				pre_reqs="$pre_reqs gnupg"
			fi
			apt_repo="deb [arch=$(dpkg --print-architecture)] $DOWNLOAD_URL/linux/$lsb_dist $dist_version $CHANNEL"
			(
				if ! is_dry_run; then
					set -x
				fi
				$sh_c 'apt-get update -qq >/dev/null'
				$sh_c "apt-get install -y -qq $pre_reqs >/dev/null"
				$sh_c "curl -fsSL \"$DOWNLOAD_URL/linux/$lsb_dist/gpg\" | apt-key add -qq - >/dev/null"
				$sh_c "echo \"$apt_repo\" > /etc/apt/sources.list.d/docker.list"
				if [ "$lsb_dist" = "debian" ] && [ "$dist_version" = "wheezy" ]; then
					$sh_c 'sed -i "/deb-src.*download\.docker/d" /etc/apt/sources.list.d/docker.list'
				fi
				$sh_c 'apt-get update -qq >/dev/null'
				$sh_c 'apt-get install -y -qq docker-ce >/dev/null'
			)
			echo_docker_as_nonroot
			exit 0
			;;
		centos|fedora)
			yum_repo="$DOWNLOAD_URL/linux/$lsb_dist/docker-ce.repo"
			if [ "$lsb_dist" = "fedora" ]; then
				if [ "$dist_version" = "24" ]; then
					echo
					echo "Warning: Fedora 24 has reached EOL"
					echo "         Support for Fedora 24 for this installation script will be removed on October 1, 2017"
					echo
					sleep 10
				fi
				if [ "$dist_version" -lt "24" ]; then
					echo "Error: Only Fedora >=24 are supported"
					exit 1
				fi
				pkg_manager="dnf"
				config_manager="dnf config-manager"
				enable_channel_flag="--set-enabled"
				pre_reqs="dnf-plugins-core"
			else
				pkg_manager="yum"
				config_manager="yum-config-manager"
				enable_channel_flag="--enable"
				pre_reqs="yum-utils"
			fi
			(
				if ! is_dry_run; then
					set -x
				fi
				$sh_c "$pkg_manager install -y -q $pre_reqs"
				$sh_c "$config_manager --add-repo $yum_repo"
				if [ "$CHANNEL" != "stable" ]; then
					$sh_c "$config_manager $enable_channel_flag docker-ce-$CHANNEL"
				fi
				$sh_c "$pkg_manager makecache"
				$sh_c "$pkg_manager install -y -q docker-ce"
			)
			echo_docker_as_nonroot
			exit 0
			;;
		raspbian)
			export DEBIAN_FRONTEND=noninteractive

			did_apt_get_update=
			apt_get_update() {
				if [ -z "$did_apt_get_update" ]; then
					( set -x; $sh_c 'sleep 3; apt-get update' )
					did_apt_get_update=1
				fi
			}

			if [ "$lsb_dist" != "raspbian" ]; then
				# aufs is preferred over devicemapper; try to ensure the driver is available.
				if ! grep -q aufs /proc/filesystems && ! $sh_c 'modprobe aufs'; then
					if uname -r | grep -q -- '-generic' && dpkg -l 'linux-image-*-generic' | grep -qE '^ii|^hi' 2>/dev/null; then
						kern_extras="linux-image-extra-$(uname -r) linux-image-extra-virtual"

						apt_get_update
						( set -x; $sh_c 'sleep 3; apt-get install -y -q '"$kern_extras" ) || true

						if ! grep -q aufs /proc/filesystems && ! $sh_c 'modprobe aufs'; then
							echo >&2 'Warning: tried to install '"$kern_extras"' (for AUFS)'
							echo >&2 ' but we still have no AUFS.  Docker may not work. Proceeding anyways!'
							( set -x; sleep 10 )
						fi
					else
						echo >&2 'Warning: current kernel is not supported by the linux-image-extra-virtual'
						echo >&2 ' package.  We have no AUFS support.  Consider installing the packages'
						echo >&2 ' "linux-image-virtual" and "linux-image-extra-virtual" for AUFS support.'
						( set -x; sleep 10 )
					fi
				fi
			fi

			# install apparmor utils if they're missing and apparmor is enabled in the kernel
			# otherwise Docker will fail to start
			if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = 'Y' ]; then
				if command -v apparmor_parser >/dev/null 2>&1; then
					echo 'apparmor is enabled in the kernel and apparmor utils were already installed'
				else
					echo 'apparmor is enabled in the kernel, but apparmor_parser is missing. Trying to install it..'
					apt_get_update
					( set -x; $sh_c 'sleep 3; apt-get install -y -q apparmor' )
				fi
			fi

			if [ ! -e /usr/lib/apt/methods/https ]; then
				apt_get_update
				( set -x; $sh_c 'sleep 3; apt-get install -y -q apt-transport-https ca-certificates' )
			fi
			if [ -z "$curl" ]; then
				apt_get_update
				( set -x; $sh_c 'sleep 3; apt-get install -y -q curl ca-certificates' )
				curl='curl -sSL'
			fi
			if ! command -v gpg > /dev/null; then
				apt_get_update
				( set -x; $sh_c 'sleep 3; apt-get install -y -q gnupg2 || apt-get install -y -q gnupg' )
			fi

			# dirmngr is a separate package in ubuntu yakkety; see https://bugs.launchpad.net/ubuntu/+source/apt/+bug/1634464
			if ! command -v dirmngr > /dev/null; then
				apt_get_update
				( set -x; $sh_c 'sleep 3; apt-get install -y -q dirmngr' )
			fi
			if [ "$dist_version" = "stretch" ]; then
				dist_version="jessie"
			fi
			(
			set -x
			echo "$docker_key" | $sh_c 'apt-key add -'
			$sh_c "mkdir -p /etc/apt/sources.list.d"
			$sh_c "echo deb \[arch=$(dpkg --print-architecture)\] https://apt.dockerproject.org/repo ${lsb_dist}-${dist_version} main > /etc/apt/sources.list.d/docker.list"
			$sh_c 'sleep 3; apt-get update; apt-get install -y -q docker-engine'
			)
			echo_docker_as_nonroot
			exit 0
			;;
	esac
	exit 1
}

get_latest_pn_onie_img() {
	if [ ! "$(docker images -q pluribus-onie-ztp 2> /dev/null)" ]; then
		echo "=============================================================================================="
		echo "Fetching pluribus onie docker image from https://github.com/amitsi/onieztp.git#:onie/docker"
		echo "=============================================================================================="
		docker build -t pluribus-onie-ztp 'https://github.com/amitsi/onieztp.git#:onie/docker'
	fi
}

run_docker_img() {
	if [ ! "$(docker ps -a | grep pluribus-onie-ztp)" ]; then
		echo "=============================================================================================="
		echo "Starting docker container: pluribus-onie-ztp on port $HTTP_PORT"
		echo "=============================================================================================="
		docker run -d --restart always --name pluribus-onie-ztp --net=host -e HTTP_PORT=$HTTP_PORT pluribus-onie-ztp
	fi
}

show_onie_access_page() {
	ipaddr=$(docker exec -i pluribus-onie-ztp sh -c "ip addr show eth0 | grep -oP 'inet \K\S+' | cut -d/ -f1")
	echo "========================================================================="
	echo "To Access Pluribus ZTP ONIE Server go to : http://$ipaddr:$HTTP_PORT"
	echo "========================================================================="
}

# wrapped up in a function so that we have some protection against only getting
# half the file during "curl | sh"
do_install

get_latest_pn_onie_img

run_docker_img

show_onie_access_page
