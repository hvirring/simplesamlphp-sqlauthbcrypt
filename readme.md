# sqlauthBcrypt

This is an authentication module for [SimpleSAMLphp](http://simplesamlphp.org) to authenticate a user against a SQL database table.

It assumes password hashes and salts are calculated using [bcrypt](http://bcrypt.sourceforge.net/).

The implementation is based heavily on the SimpleSAMLphp module [sqlauth:SQL](https://github.com/simplesamlphp/simplesamlphp-module-sqlauth).

## Installation

- Download the module to your SimpleSAMLphp modules directory
- Configure the Authentication Source in config/authsources.php
- Enable the module in your config.php under `module.enable`

```php
    'module.enable' => [
        'sqlauthbcrypt' => true
    ],
```

## Usage

In authsource.php:

```php
    'bcrypt-example' => array(
      'sqlauthbcrypt:SQL',
      'dsn' => 'mysql:host=sql.example.org;dbname=simplesaml',
      'username' => 'userdb',
      'password' => 'secretpassword',
      'hash_column' => 'password_hash',
      'query' => 'SELECT username AS uid, name AS cn, email AS mail, password_hash FROM users WHERE username = :username',
      'pepper' => '0474f00f7823ade',
    ),
```

`dsn`
:   The DSN which should be used to connect to the database server. Check the various database drivers in the [PHP documentation](http://php.net/manual/en/pdo.drivers.php) for a description of the various DSN formats.

`username`
:   The username which should be used when connecting to the database server.

`password`
:   The password which should be used when connecting to the database server. If you are running this locally for development and you are using an empty password, set this to the empty string ('').

`query`
:   The SQL query which should be used to retrieve the user. The parameters :username and :password are available. If the username/password is incorrect, the query should return no rows. The name of the columns in resultset will be used as attribute names. If the query returns multiple rows, they will be merged into the attributes. Duplicate values and NULL values will be removed.

`pepper`
:   The pepper string appended to passwords before generating the hash. If you are not using a pepper, set this to the empty string ('').

`hash_column`
:   The column storing password hashes.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
