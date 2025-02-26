using System;

namespace Expert1.CloudSqlProxy
{
    internal static class Utilities
    {
        private static string _userAgent;
        public static string UserAgent
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_userAgent))
                {
                    _userAgent = $"Expert1.CloudSqlProxy/{GetVersion()}";
                }

                return _userAgent;
            }
        }

        private static string GetVersion() => typeof(ProxyInstance).Assembly.GetName().Version.ToString(3);

        public static (string project, string region, string name) SplitName(string instance)
        {
            ReadOnlySpan<char> span = instance.AsSpan();
            int firstColon = span.IndexOf(':');
            if (firstColon == -1)
            {
                return ("", "", instance);
            }

            int secondColon = span[(firstColon + 1)..].IndexOf(':');
            if (secondColon != -1)
            {
                secondColon += firstColon + 1;
            }

            int dotIndex = span[..firstColon].IndexOf('.');

            if (dotIndex != -1 && secondColon != -1)
            {
                // Handle case where first segment contains a dot and there are two colons
                string project = new(span[..secondColon]);
                int thirdColon = span[(secondColon + 1)..].IndexOf(':');
                if (thirdColon != -1)
                {
                    thirdColon += secondColon + 1;
                    string region = new(span.Slice(secondColon + 1, thirdColon - secondColon - 1));
                    string name = new(span[(thirdColon + 1)..]);
                    return (project, region, name);
                }
                else
                {
                    string region = new(span[(secondColon + 1)..]);
                    return (project, region, "");
                }
            }
            else if (secondColon == -1)
            {
                string project = new(span[..firstColon]);
                string name = new(span[(firstColon + 1)..]);
                return (project, "", name);
            }
            else
            {
                string project = new(span[..firstColon]);
                string region = new(span.Slice(firstColon + 1, secondColon - firstColon - 1));
                string name = new(span[(secondColon + 1)..]);
                return (project, region, name);
            }
        }
    }
}
