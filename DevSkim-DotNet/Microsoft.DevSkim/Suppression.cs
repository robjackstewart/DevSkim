// Copyright (C) Microsoft. All rights reserved. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.ApplicationInspector.RulesEngine;

namespace Microsoft.DevSkim
{
    /// <summary>
    ///     Processor for rule suppressions
    /// </summary>
    public class Suppression
    {
        protected const string KeywordAll = "all";
        protected const string KeywordIgnore = "ignore";
        protected const string KeywordPrefix = "DevSkim:";
        protected const string KeywordUntil = "until";
        protected const string KeywordBy = "by";
        public const string PATTERN = KeywordPrefix + @"\s+" + KeywordIgnore + @"\s([a-zA-Z\d,:]+)(\s+" + KeywordUntil + @"\s\d{4}-\d{2}-\d{2}|)(\s+" + KeywordBy + @"\s([A-Za-z0-9_]+)|)";
        public const string DATETIME_FORMAT = "yyyy-MM-dd";

        public readonly Line? Line;
        public ImmutableArray<SuppressedIssue> Issues { get; private set; } = new();
        public Boundary Boundary { get; private set; }
        public DateTime? ExpirationDate { get; private set; } = null;
        public Boundary? IssuesBoundary { get; private set; }
        public string? Reviewer { get; private set; } = string.Empty;
        public bool IsInEffect => HasIssues() && !IsExpired();
        public string[] GetSuppressedIds => IssueBoundarysById.Keys.OrderBy(k => k).ToArray();
        public readonly string? Prefix = null;
        public readonly string? Suffix = null;
        private readonly Dictionary<string, Boundary> IssueBoundarysById = new();

        private Suppression(string? reviewer, DateTime? expirationDate, Dictionary<string, Boundary> issueBoundarysById, Line? line, Boundary boundary, Boundary? issuesBoundary)
        {
            ExpirationDate = expirationDate;
            IssueBoundarysById = issueBoundarysById;
            Line = line;
            Boundary = boundary;
            Reviewer = reviewer is null ? string.Empty : reviewer;
            IssuesBoundary = issuesBoundary;
        }

        public Suppression(string? reviewer, DateTime? expirationDate, IEnumerable<string> issueIds, Line line)
        {
            Line = line;
            Reviewer = reviewer;
            ExpirationDate = expirationDate;
            if (line is not null)
            {
                var lineParseResult = LineParseResult.From(line);
                Boundary = lineParseResult.SuppressionBoundary;
                IssueBoundarysById = new Dictionary<string, Boundary>(lineParseResult.IssueBoundarysById);
                AddIssues(issueIds);
            }
            else
            {
                IssueBoundarysById = new Dictionary<string, Boundary>();
                AddIssues(issueIds);
                var suppressionString = GetSuppressionString(IssueBoundarysById.Keys, ExpirationDate, Reviewer);
                Boundary = new Boundary { Index = 0, Length = suppressionString.Length };
            }
            
        }

        public Suppression(string? reviewer, DateTime? expirationDate, IEnumerable<string> issueIds, string? prefix = null, string? suffix = null)
        {
            Reviewer = reviewer;
            ExpirationDate = expirationDate;
            IssueBoundarysById = new Dictionary<string, Boundary>();
            Prefix = prefix;
            Suffix = suffix;
            AddIssues(issueIds);
            var suppressionString = GetSuppressionString(IssueBoundarysById.Keys, ExpirationDate, Reviewer);
            Boundary = new Boundary { Index = 0, Length = suppressionString.Length };

        }

        public Suppression(string? reviewer, DateTime? expirationDate, string issueId, Line line)
            : this(reviewer, expirationDate, new[] { issueId }, line)
        {

        }

        public Suppression(string? reviewer, DateTime? expirationDate, string issueId, string? prefix = null, string? suffix = null)
            : this(reviewer, expirationDate, new[] { issueId }, prefix, suffix)
        {

        }

        public void AddIssue(string issueId)
        {
            if (!IssueBoundarysById.ContainsKey(issueId))
            {
                IssueBoundarysById.Add(issueId, new Boundary());
            }
        }

        public void AddIssues(IEnumerable<string> issueIds)
        {
            foreach (var issueId in issueIds)
            {
                AddIssue(issueId);
            }
        }

        public bool IsExpired()
            => ExpirationDate.HasValue && DateTime.Now > ExpirationDate.Value;

        public bool HasIssues()
            => IssueBoundarysById.Count > 0;

        public static Regex GetRegex()
            => new(PATTERN, RegexOptions.IgnoreCase);

        public static Suppression From(string line)
            => From(new Line(line));

        public static Suppression From(Line line)
        {
            var lineParseResult = LineParseResult.From(line);
            return new Suppression(lineParseResult.Reviewer, lineParseResult.ExpirationDate, new Dictionary<string, Boundary>(lineParseResult.IssueBoundarysById), line, lineParseResult.SuppressionBoundary, lineParseResult.IssuesListBoundary);
        }

        /// <summary>
        ///     Test if given rule Id is being suppressed
        /// </summary>
        /// <param name="issueId"> Rule ID </param>
        /// <returns> True if rule is suppressed </returns>
        public SuppressedIssue? GetSuppressedIssue(string issueId)
        {
            if (DateTime.Now > ExpirationDate)
            {
                return null;
            }

            if (IssueBoundarysById.TryGetValue(issueId, out var issueBoundary))
            {
                return new SuppressedIssue
                {
                    ID = issueId,
                    Boundary = issueBoundary
                };
            }

            if (IssueBoundarysById.TryGetValue(KeywordAll, out var alIssuesBoundary))
            {
                return new SuppressedIssue
                {
                    ID = KeywordAll,
                    Boundary = alIssuesBoundary
                };
            }

            return null;
        }

        public string ToSuppressionString(string? prefix = null, string? suffix = null)
            => GetSuppressionString(IssueBoundarysById.Keys, ExpirationDate, Reviewer, prefix, suffix);

        public static string GetSuppressionString(IEnumerable<string> issueIds, DateTime? expirationDate, string? reviewer, string? prefix = null, string? suffix = null)
        {
            var sb = new StringBuilder();
            foreach (var issueId in issueIds)
            {
                if (!string.IsNullOrEmpty(prefix))
                {
                    sb.Append($"{prefix} ");
                }
                sb.Append($"DevSkim: ignore {issueId}");

                if (expirationDate.HasValue)
                {
                    sb.Append($" until {expirationDate.Value}");
                }
                if (!string.IsNullOrEmpty(reviewer))
                {
                    sb.Append($" by {reviewer}");
                }
                if (!string.IsNullOrEmpty(suffix))
                {
                    sb.Append($" {suffix}");
                }
            }
            return sb.ToString();

        }

        private class LineParseResult
        {
            public readonly ImmutableDictionary<string, Boundary> IssueBoundarysById = ImmutableDictionary<string, Boundary>.Empty;
            public readonly Boundary SuppressionBoundary;
            public readonly Boundary? IssuesListBoundary;
            public readonly string? Reviewer;
            public readonly DateTime? ExpirationDate;
            public readonly Line Line;

            private LineParseResult(Line line, ImmutableDictionary<string, Boundary> issueBoundarysById, Boundary suppressionBoundary, string? reviewer, DateTime? expirationDate)
            {
                Line = line;
                if (issueBoundarysById is not null)
                {
                    IssueBoundarysById = issueBoundarysById;
                }
                SuppressionBoundary = suppressionBoundary;
                Reviewer = reviewer;
                ExpirationDate = expirationDate;
                IssuesListBoundary = IssueBoundarysById is not null && IssueBoundarysById.Count > 0 ? IssuesListBoundary = new Boundary
                    {
                        Index = IssueBoundarysById.Min(i => i.Value.Index),
                        Length = IssueBoundarysById.Sum(i => i.Value.Length)
                    } : null;
                
            }

            public static LineParseResult From(Line line)
            {
                DateTime? expirationDate = null;
                var reg = GetRegex();
                string? reviewer = null;
                var suppressionBoundary = new Boundary { Index = -1, Length = 0 };
                var issueBoundarysById = new Dictionary<string, Boundary>();

                Match match = reg.Match(line.Content);

                if (match.Success)
                {
                    suppressionBoundary = new Boundary {  Index = match.Index, Length = match.Length };

                    string idString = match.Groups[1].Value.Trim();
                    var issuesListIndex = match.Groups[1].Index;

                    // Parse Reviewer
                    if (match.Groups.Count > 4 && !string.IsNullOrEmpty(match.Groups[4].Value))
                    {
                        reviewer = match.Groups[4].Value;
                    }

                    // Parse date
                    if (match.Groups.Count > 2 && !string.IsNullOrEmpty(match.Groups[2].Value))
                    {
                        string date = match.Groups[2].Value;
                        reg = new Regex(@"(\d{4}-\d{2}-\d{2})");
                        Match m = reg.Match(date);
                        if (m.Success)
                        {
                            try
                            {
                                expirationDate = DateTime.ParseExact(m.Value, DATETIME_FORMAT, System.Globalization.CultureInfo.InvariantCulture);
                            }
                            catch (FormatException)
                            {
                                expirationDate = null;
                            }
                        }
                    }

                    // parse Ids.
                    if (idString == KeywordAll)
                    {
                        issueBoundarysById.Add(KeywordAll, new Boundary()
                        {
                            Index = issuesListIndex,
                            Length = KeywordAll.Length
                        });
                    }
                    else
                    {
                        string[] ids = idString.Split(',');
                        int index = issuesListIndex;
                        foreach (string id in ids)
                        {
                            issueBoundarysById.Add(id, new Boundary()
                            {
                                Index = issuesListIndex,
                                Length = KeywordAll.Length
                            });
                            index += id.Length + 1;
                        }
                    }
                }
                return new LineParseResult(line, issueBoundarysById.ToImmutableDictionary(), suppressionBoundary, reviewer, expirationDate);
            }

            public Suppression? ToSuppression()
            {
                if (SuppressionBoundary is null)
                {
                    return null;
                }

                return new Suppression(Reviewer, ExpirationDate, new Dictionary<string, Boundary>(IssueBoundarysById), Line, SuppressionBoundary, IssuesListBoundary);
            }
        }
    }
}