using BasicAuthentication.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace BasicAuthentication.mappings;

public class UserMapping : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(x => x.Id);


        builder.Property(i => i.UserName)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(i => i.Password)
            .IsRequired();

    }
}
