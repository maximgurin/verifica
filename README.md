[![CI](https://github.com/maximgurin/verifica/actions/workflows/ci.yml/badge.svg)](https://github.com/maximgurin/verifica/actions/workflows/ci.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/457e56b0bb514539844a94d85abe99f9)](https://www.codacy.com/gh/maximgurin/verifica/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=maximgurin/verifica&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/457e56b0bb514539844a94d85abe99f9)](https://www.codacy.com/gh/maximgurin/verifica/dashboard?utm_source=github.com&utm_medium=referral&utm_content=maximgurin/verifica&utm_campaign=Badge_Coverage)
![GitHub](https://img.shields.io/github/license/maximgurin/verifica)

# Verifica

Verifica is Ruby's most scalable authorization solution ready to handle sophisticated authorization rules.

- Framework and database agnostic
- Scalable. Start from 10, grow to 10M records in the database while having the same authorization architecture
- Supports any type of actor in your application. Traditional `current_user`, external service, API client, you name it
- No global state. Only local, immutable objects
- Plain old Ruby, zero dependencies, no magic

Verifica is designed around Access Control List. ACL clearly separates authorization rules definition
(who can do what for any given resource) and execution (can `current_user` delete this post?).

**Note: Verifica is under active development. The first public release, docs, and examples are coming soon.**

## Why Verifica? Isn't Pundit or CanCanCan enough?

Let's say you working on a video platform application:

- You have 10M videos in the database
- 7 types of user roles
- 20 rules dictating who is allowed to access the video
- Rules require querying other entities too (video author settings, author's organization settings, etc.)

Given all these, *how do you even find a list of videos available for `current_user`?*
Bunch of `if/elsif` and enormous SQL query with many joins? Is there a better way? Verifica shines for this kind of problem.

## Basic example

```ruby
require 'verifica'

User = Struct.new(:id, :role, keyword_init: true) do
  # Verifica expects each security subject to reply to #subject_id, #subject_type, and #subject_sids
  alias_method :subject_id, :id
  def subject_type = :user

  def subject_sids(**)
    role == "root" ? ["root"] : ["authenticated", "user:#{id}"]
  end
end

Video = Struct.new(:id, :author_id, :public, keyword_init: true) do
  # Verifica expects each secured resource to reply to #resource_id, and #resource_type
  alias_method :resource_id, :id
  def resource_type = :video
end

video_acl_provider = lambda do |video, **|
  Verifica::Acl.build do |acl|
    acl.allow "root", [:read, :write, :delete, :comment]
    acl.allow "user:#{video.author_id}", [:read, :write, :delete, :comment]

    if video.public
      acl.allow "authenticated", [:read, :comment]
    end
  end
end

authorizer = Verifica.authorizer do |config|
  config.register_resource :video, [:read, :write, :delete, :comment], video_acl_provider
end

public_video = Video.new(id: 1, author_id: 1000, public: true)
private_video = Video.new(id: 2, author_id: 1000, public: true)

superuser = User.new(id: 777, role: "root")
video_author = User.new(id: 1000, role: "user")
other_user = User.new(id: 2000, role: "user")

authorizer.authorized?(superuser, private_video, :delete)
# true

authorizer.authorized?(video_author, private_video, :delete)
# true

authorizer.authorized?(other_user, private_video, :read)
# false

authorizer.authorized?(other_user, public_video, :comment)
# true

authorizer.authorize(other_user, public_video, :write)
# raises Verifica::AuthorizationError: Authorization FAILURE. Subject 'user' id='2000'. Resource 'video' id='1'. Action 'write'
```

## Installation

Install the gem and add to the application's Gemfile by executing:

```bash
$ bundle add verifica
```

## Core concepts

Get a high-level overview of Verifica's core concepts and architecture before diving into usage nuances.
Verifica may appear complex initially, but it prioritizes explicitness, flexibility, and scalability over nice looking magic.
Here is an explanation of each component:

### Subject

Security subject is a user, process, or system granted access to specific resources.
In most applications the subject is currently authenticated user, aka `current_user`.

In code a subject could be represented by any object that responds to `subject_id`, `subject_type`, and `subject_sids`.

```ruby
class User
  def subject_id
    123
  end
  
  def subject_type
    :user
  end
  
  def subject_sids
    ["root"] # see Security Identifier section below to understand what is this for
  end
end
```

### Resource

Resource refers to anything that requires protection.
In most applications resources are entities stored in the database, such are Post, Comment, User, etc.

In code a resource could be represented by any object that responds to `resource_id` and `resource_type`.

```ruby
class Post
  def resource_id
    1
  end
  
  def resource_type
    :post
  end
end
```

### Action

Action that Subject attempts to perform on a protected Resource. Represented as a Symbol in code,
it could be traditional `:read`, `:write`, `:delete` or more domain specific `:comment`, `:publish`, etc.

### Security Identifier

SID is a value used to identify and differentiate Subjects
and assign access rights based on the subject's attributes like role, organization, group, or country.

In code SID could be represented by immutable string (other objects work too, equality check is the only requirement).
Each subject has one or more SIDs.

```ruby
superuser.subject_sids         # => ["root"]
moderator_user.subject_sids    # => ["user:321", "role:moderator"]
regular_user.subject_sids      # => ["authenticated", "user:123", "country:UA"]
organization_user.subject_sids # => ["authenticated", "user:456", "country:UA", "org:789"]
anonymous_user.subject_sids    # => ["anonymous", "country:UA"]
```

### Access Control List

ACL consists of Access Control Entities (ACEs) and defines which actions are allowed or denied for particular SIDs.
ACL is associated with a particular protected resource in your system.

```ruby
video_acl = Verifica::Acl.build do |acl|
  acl.allow "authenticated", [:read, :comment]
  acl.deny "country:US", [:read]
end

video_acl.to_a
# =>
# [#<Verifica::Ace:0x00007fab1955dd60 @action=:view, @allow=true, @sid="authenticated">,          
#  #<Verifica::Ace:0x00007fab1955dd10 @action=:comment, @allow=true, @sid="authenticated">,       
#  #<Verifica::Ace:0x00007fab1955dc48 @action=:view, @allow=false, @sid="country:US">]
```

### AclProvider

AclProvider is an object that responds to `call(resource, **)` and returns ACL for the given resource.

```ruby
class VideoAclProvider
  def call(video, **context)
    Verifica::Acl.build do |acl|
      acl.allow "user:#{video.author_id}", [:read, :write, :delete, :comment]

      if video.public?
        acl.allow "authenticated", [:read, :comment]
      end
    end
  end
end
```

### Authorizer

And finally, Authorizer, the heart of Verifica. It couples all concepts above into an isolated container with no global state.
Each Authorizer has a list of resource types registered with their companion AclProviders.
And most importantly, Authorizer has several methods to check the Subject's rights to perform a specific action on a given resource.

Check the [Basic example](#basic-example) above to see how it all plays together.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests.
You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`,
which will create a git tag for the version, push git commits and the created tag,
and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/maximgurin/verifica.
This project is intended to be a safe, welcoming space for collaboration, and contributors are expected
to adhere to the [code of conduct](https://github.com/maximgurin/verifica/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Verifica project's codebases, issue trackers, chat rooms and mailing lists is
expected to follow the [code of conduct](https://github.com/maximgurin/verifica/blob/master/CODE_OF_CONDUCT.md).
