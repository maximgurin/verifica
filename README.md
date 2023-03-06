[![Gem Version](https://badge.fury.io/rb/verifica.svg)](https://badge.fury.io/rb/verifica)
[![CI](https://github.com/maximgurin/verifica/actions/workflows/ci.yml/badge.svg)](https://github.com/maximgurin/verifica/actions/workflows/ci.yml)
[![Yard Docs](http://img.shields.io/badge/yard-docs-blue.svg)](http://rubydoc.info/github/maximgurin/verifica)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/457e56b0bb514539844a94d85abe99f9)](https://www.codacy.com/gh/maximgurin/verifica/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=maximgurin/verifica&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/457e56b0bb514539844a94d85abe99f9)](https://www.codacy.com/gh/maximgurin/verifica/dashboard?utm_source=github.com&utm_medium=referral&utm_content=maximgurin/verifica&utm_campaign=Badge_Coverage)
![GitHub](https://img.shields.io/github/license/maximgurin/verifica)

# Verifica

Verifica is Ruby's most scalable authorization solution ready to handle sophisticated authorization rules.

- Framework and database agnostic
- Scalable. Start from 10, grow to 10M records in the database while having the same authorization architecture
- Supports any actor in your application. Traditional `current_user`, external service, API client, you name it
- No global state. Only local, immutable objects
- Plain old Ruby, zero dependencies, no magic

Verifica is designed around Access Control List. ACL powers a straightforward and unified authorization flow
for any user and resource, regardless of how complex the authorization rules are.

*Note: Verifica is a new open-source gem, so you may wonder if it's reliable. Internally,
this solution has been battle-tested in several B2B products, including one with over 15M database records.
But anyway, trust nothing. DYOR.*

## Why Verifica? Isn't Pundit or CanCanCan enough?

Let's say you are working on a video platform application:

- You have 10M videos in the database
- 7 types of user roles
- 20 rules defining who is allowed to access the video
- Rules require querying other entities too (video author settings, author's organization settings, etc.)

Given all these, *how do you even find a list of videos available for `current_user`?*
Bunch of `if/elsif` and enormous SQL query with many joins? Is there a better way? Verifica shines for this kind of problem.
In the [Real-world example with Rails](#real-world-example-with-rails) you can see the solution in detail.

## Basic example

```ruby
require 'verifica'

User = Struct.new(:id, :role, keyword_init: true) do
  # Verifica expects each security subject to respond to #subject_id, #subject_type, and #subject_sids
  alias_method :subject_id, :id
  def subject_type = :user

  def subject_sids(**)
    role == "root" ? ["root"] : ["authenticated", "user:#{id}"]
  end
end

Video = Struct.new(:id, :author_id, :public, keyword_init: true) do
  # Verifica expects each secured resource to respond to #resource_id, and #resource_type
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
private_video = Video.new(id: 2, author_id: 1000, public: false)

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

**Required Ruby version >= 3.0**

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

In code a subject could be represented by any object that responds to `#subject_id`, `#subject_type`, and `#subject_sids`.

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
In most applications resources are entities stored in the database, such as Post, Comment, User, etc.

In code a resource could be represented by any object that responds to `#resource_id` and `#resource_type`.

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

Action that Subject can perform on a protected Resource. Represented as a Symbol in code,
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

ACL consists of Access Control Entries (ACEs) and defines which actions are allowed or denied for particular SIDs.
ACL is associated with a specific protected resource in your system.

```ruby
video_acl = Verifica::Acl.build do |acl|
  acl.allow "authenticated", [:read, :comment]
  acl.deny "country:US", [:read]
end

video_acl.to_a
# =>
# [#<Verifica::Ace:0x00007fab1955dd60 @action=:read, @allow=true, @sid="authenticated">,
#  #<Verifica::Ace:0x00007fab1955dd10 @action=:comment, @allow=true, @sid="authenticated">,
#  #<Verifica::Ace:0x00007fab1955dc48 @action=:read, @allow=false, @sid="country:US">]
```

### AclProvider

AclProvider is an object that responds to `#call(resource, **)` and returns ACL for the given resource.

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
Each Authorizer has a list of resource types registered with their companion AclProviders and
several methods to check the Subject's rights to perform a specific action on a given resource.

Check the [Basic example](#basic-example) above to see how it all plays together.

## Real-world example with Rails

Demo: https://verifica-rails-example.maximgurin.com

Let's say you started working on your *next big thing* idea — a video hosting application.
In the beginning, you have only 2 user types and straightforward rules:

- *Admins* can see all videos
- *Users* can see their own videos and public videos of other users

```ruby
class Video
  scope :available_for, ->(user) do
    where(public: true).or(where(author_id: user.id)) unless user.admin?
  end
end

class VideosController
  def index
    @videos = Video.available_for(current_user)
  end
end
```

Time goes by and 4 years later you have:

- 10M records in the videos table. Organization and personal user accounts
- 4 roles: *Admin*, *Moderator*, *Organization Admin*, *User*
- Video drafts available only to their authors
- Internal videos available only for members of the author's organization
- Country restrictions, either in the *allowlist* or *denylist* modes
- Distribution Settings entity with one-to-many relation to Videos
  - Distribution mode: *public*, *internal*, or *private*
  - Countries *allowlist* or *denylist*
- Organization-wide country restrictions overrides Distribution Settings
- *Organization Admins* can see private videos of their org members
- *Admins* and *Moderators* can see all videos, regardless of country restrictions

Wow, that's a pretty extensive list of requirements. Easy to get lost!
Now the most exciting part. How do you implement `Video.available_for` method with so many details to consider?
Videos table is big, so you can't use SQL joins to, let's say, check the video author's organization or other dependencies.
And even if you can, a query with so many joins and conditions would be write-only anyway :)

Here is how this challenge could be resolved using Verifica and ACL:

```ruby
# app/acl_providers/video_acl_provider.rb

class VideoAclProvider
  include Verifica::Sid

  POSSIBLE_ACTIONS = [:read, :write, :delete].freeze

  def call(video, **)
    Verifica::Acl.build do |acl|
      acl.allow root_sid, POSSIBLE_ACTIONS
      acl.allow user_sid(video.author_id), POSSIBLE_ACTIONS
      acl.allow role_sid("moderator"), [:read, :delete]

      next if video.draft?

      ds = video.distribution_setting
      author_org = video.author.organization
      allowed_countries = author_org&.allow_countries || ds.allow_countries
      denied_countries = author_org&.deny_countries || ds.deny_countries
      
      # ...and 30 more lines to handle all our requirements
    end
  end
end
```

```ruby
# config/initializers/verifica.rb

require "verifica"

# Quick and dirty way for simplicity
# In the real app, you could use DI container to hold configured Verifica::Authorizer instance
Rails.configuration.after_initialize do
  AUTHORIZER = Verifica.authorizer do |config|
    config.register_resource :video, VideoAclProvider::POSSIBLE_ACTIONS, VideoAclProvider.new
  end
end
```

```ruby
# app/models/user.rb

class User < ApplicationRecord
  include Verifica::Sid

  alias_method :subject_id, :id

  def subject_type = :user

  def subject_sids(**)
    case role
    when "root"
      [root_sid]
    when "moderator"
      [user_sid(id), role_sid("moderator")]
    when "user"
      sids = [authenticated_sid, user_sid(id), "country:#{country}"]
      organization_id.try { |org_id| sids.push(organization_sid(org_id)) }
      sids
    when "organization_admin"
      sids = [authenticated_sid, user_sid(id), "country:#{country}"]
      sids.push(organization_sid(organization_id))
      sids.push(role_sid("organization_admin:#{organization_id}"))
    else
      throw RuntimeError("Unsupported user role: #{role}")
    end
  end
end
```

What we've done:

- Configured `Verifica::Authorizer` object. It's available as `AUTHORIZER` constant anywhere in the app
- Registered `:video` type as a secured resource. `VideoAclProvider` defines rules, who can do what
- Configured `User` to be a security Subject. Each user has list of Security Identifiers depending on the role and other attributes

Now, a few last steps and the challenge resolved:

```ruby
# db/migrate/20230113203815_add_read_sids_to_videos.rb

# For simplicity, we are adding two String array columns directly to videos table.
# In the real app, you could use something like ElasticSearch to hold videos with these companion columns
class AddReadSidsToVideos < ActiveRecord::Migration[7.0]
  def change
    add_column :videos, :read_allow_sids, :string, null: false, array: true, default: [], index: true
    add_column :videos, :read_deny_sids, :string, null: false, array: true, default: [], index: true
  end
end
```

```ruby
# app/models/video.rb

class Video < ApplicationRecord
  attr_accessor :allowed_actions
  alias_method :resource_id, :id

  before_save :update_read_acl

  def resource_type = :video
  
  def update_read_acl
    acl = AUTHORIZER.resource_acl(self)
    self.read_allow_sids = acl.allowed_sids(:read)
    self.read_deny_sids = acl.denied_sids(:read)
  end

  # And finally, this is our goal. Straightforward implementation regardless of how complex the rules are.
  scope :available_for, ->(user) do
    sids = user.subject_sids
    where("read_allow_sids && ARRAY[?]::varchar[]", sids).where.not("read_deny_sids && ARRAY[?]::varchar[]", sids)
  end
end
```

```ruby
# app/controllers/videos_controller

class VideosController
  def index
    @videos = Video
      .includes(:distribution_setting, author: [:organization])
      .available_for(current_user)
      .order(:name)
      .limit(50)
  end
  
  def show
    @video = Video.find(params[:id])
    
    # upon successful authorization helper object is returned with a bunch of useful info
    auth_result = AUTHORIZER.authorize(current_user, @video, :read)

    # add list of allowed actions so the frontend knows whether show "Edit" and "Delete" buttons, for example
    @video.allowed_actions = auth_result.allowed_actions
  end

  def destroy
    video = Video.find(params[:id])
    AUTHORIZER.authorize(current_user, video, :delete)
    video.destroy
  end
end
```

Voila, we're done! So now, no matter how sophisticated our authorization rules are,
we have a clear method to find available videos for any user.
No conditions, no special handling for superusers as everyone goes through the unified mechanism.

**Important points not covered in this example but needed in the real app**:

- **Dependency change handling.** If country restrictions changed on the organization level you need to
run a background job to find all affected videos and update `read_allow_sids`, `read_deny_sids` columns.
Same applies to Distribution Settings and other dependencies.
- **Rules change handling.** If implementation of `VideoAclProvider` changed you need to run a background job
to update `read_allow_sids`, `read_deny_sids` columns for all videos.

See also:

- Live demo - https://verifica-rails-example.maximgurin.com
- Full source code - https://github.com/maximgurin/verifica-rails-example

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
